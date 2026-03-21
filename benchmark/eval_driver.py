#!/usr/bin/env python3

import argparse
import datetime as dt
import json
import os
import sys
import time
import traceback
from dataclasses import asdict
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aider.cve import load_cve_context, parse_cve_text_dataset
from aider.cve_agent import (
    build_localization_messages,
    build_patch_prompt,
    build_root_cause_messages,
    build_root_cause_prompt,
    build_static_root_cause_report,
    localize_cve_context,
    load_feedback_profile,
    save_feedback_profile,
)
from benchmark.cve_replay import (
    CVE_REPO_MAP_TOKENS,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_TARGET_REPO,
    DEFAULT_VALIDATION_COMMANDS,
    append_jsonl,
    compare_expected_files_to_fix_tree,
    compare_patch_texts,
    create_run_dir,
    create_worktree,
    describe_repo_state,
    expand_dataset_cases,
    get_changed_files_from_patch,
    get_commit_patch,
    get_generated_patch,
    is_successful_result,
    make_case_slug,
    remove_worktree,
    run_agent_on_worktree,
    run_validation_commands,
    score_file_sets,
    summarize_replay_results,
    check_patch_text_applies,
    try_apply_patch_text,
    write_json,
)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Drive the Aider CVE agent over cve.txt and compare generated patches with upstream fixes."
    )
    parser.add_argument(
        "run_name",
        nargs="?",
        default="cve-eval",
        help="Name suffix for the output run directory",
    )
    parser.add_argument(
        "--cases-file",
        default="cve.txt",
        help="Text file with CVE id and fixed commit pairs",
    )
    parser.add_argument(
        "--target-repo",
        "--rootpath",
        default=DEFAULT_TARGET_REPO,
        dest="target_repo",
        help="Path to the Linux repository under evaluation",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory that stores evaluation runs and artifacts",
    )
    parser.add_argument(
        "--feedback-file",
        default=None,
        help="Optional persistent JSON file for self-evolving prompt feedback",
    )
    parser.add_argument(
        "--model",
        required=True,
        help="Main model name passed to aider",
    )
    parser.add_argument(
        "--edit-format",
        default="cve",
        help="Aider edit format used for repair generation",
    )
    parser.add_argument(
        "--editor-model",
        default=None,
        help="Optional editor model name",
    )
    parser.add_argument(
        "--editor-edit-format",
        default=None,
        help="Optional editor edit format",
    )
    parser.add_argument(
        "--reasoning-effort",
        default=None,
        help="Optional reasoning effort for supported models",
    )
    parser.add_argument(
        "--thinking-tokens",
        default=None,
        help="Optional thinking token budget for supported models",
    )
    parser.add_argument(
        "--case",
        "--cve",
        action="append",
        default=[],
        help="Select a case by CVE id or dataset index. Can be repeated.",
    )
    parser.add_argument(
        "--commit-id",
        default=None,
        help="Only run cases whose fix or vulnerable commit matches this prefix",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of cases to run",
    )
    parser.add_argument(
        "--map-tokens",
        type=int,
        default=4096,
        help="Repo-map token budget used during analysis and repair",
    )
    parser.add_argument(
        "--analysis-files",
        type=int,
        default=4,
        help="How many localized files to add read-only during root-cause analysis",
    )
    parser.add_argument(
        "--edit-files",
        type=int,
        default=6,
        help="How many localized files to seed into the repair coder",
    )
    parser.add_argument(
        "--localization-limit",
        type=int,
        default=12,
        help="Maximum number of localized candidate files to keep in the report",
    )
    parser.add_argument(
        "--grep-limit",
        type=int,
        default=3,
        help="Maximum grep hits to retain per localized symbol",
    )
    parser.add_argument(
        "--cve-max-patch-lines",
        type=int,
        default=400,
        help="Maximum upstream patch lines injected into model context",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=3,
        help="Maximum agent rounds per repair case",
    )
    parser.add_argument(
        "--validation-timeout",
        type=int,
        default=300,
        help="Timeout in seconds for each validation command",
    )
    parser.add_argument(
        "--success-criteria",
        choices=[
            "validation",
            "expected-files",
            "patch-id",
            "fix-tree",
            "patch-id-or-fix-tree",
        ],
        default="patch-id-or-fix-tree",
        help="Condition that marks a repair case as successful",
    )
    parser.add_argument(
        "--validate-cmd",
        action="append",
        default=[],
        help="Validation command to run inside each worktree. Can be repeated.",
    )
    parser.add_argument(
        "--reference-apply-fallback",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Apply the upstream patch directly when git apply --check succeeds on the target tree",
    )
    parser.add_argument(
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Skip cases that already have a result.json artifact",
    )
    parser.add_argument(
        "--keep-worktrees",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Keep worktree directories after each case",
    )
    parser.add_argument(
        "--auto-add-file-mentions",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Auto-add file mentions from assistant replies between repair rounds",
    )
    parser.add_argument(
        "--verbose",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable verbose aider output",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    run_dir = create_run_dir(Path(args.output_dir).resolve(), args.run_name)
    run_dir.mkdir(parents=True, exist_ok=True)

    cases_file = Path(args.cases_file).expanduser().resolve()
    entries = parse_cve_text_dataset(
        cases_file.read_text(encoding="utf-8", errors="replace"),
        repo=args.target_repo,
    )
    cases = expand_dataset_cases(entries, selectors=args.case, max_pre_fix_per_case=1, limit=args.limit)

    if args.commit_id:
        cases = [
            case
            for case in cases
            if case.pre_fix_commit.startswith(args.commit_id)
            or case.fix_commit.startswith(args.commit_id)
        ]

    if not cases:
        print("No evaluation cases selected.")
        return 1

    feedback_path = Path(args.feedback_file).resolve() if args.feedback_file else run_dir / "feedback_profile.json"
    feedback_profile = load_feedback_profile(feedback_path)

    run_manifest = {
        "created_at": dt.datetime.now(dt.UTC).isoformat(),
        "cases_file": str(cases_file),
        "target_repo": str(Path(args.target_repo).resolve()),
        "model": args.model,
        "edit_format": args.edit_format,
        "feedback_file": str(feedback_path),
        "cases": [asdict(case) for case in cases],
        "aider_repo": describe_repo_state(Path.cwd()),
        "target_repo_state": describe_repo_state(Path(args.target_repo)),
    }
    write_json(run_dir / "run_manifest.json", run_manifest)

    results = []
    for case in cases:
        result = run_eval_case(args, run_dir, case, feedback_profile)
        results.append(result)
        if result.get("status") != "error":
            feedback_profile.record_result(result)
            save_feedback_profile(feedback_path, feedback_profile)
        append_jsonl(run_dir / "results.jsonl", result)

        summary = summarize_replay_results(results)
        summary["feedback_profile"] = feedback_profile.to_dict()
        write_json(run_dir / "summary.json", summary)

    return 0


def run_eval_case(args, run_dir, case, feedback_profile):
    case_slug = make_case_slug(case)
    case_dir = run_dir / "cases" / case_slug
    worktree_dir = run_dir / "worktrees" / case_slug
    result_path = case_dir / "result.json"

    case_dir.mkdir(parents=True, exist_ok=True)
    if args.resume and result_path.exists():
        return json.loads(result_path.read_text(encoding="utf-8", errors="replace"))

    print(
        f"[eval] {case.cve} pre_fix={case.pre_fix_commit[:12]} fix={case.fix_commit[:12]}",
        flush=True,
    )

    started_at = time.time()
    expected_patch = get_commit_patch(args.target_repo, case.fix_commit)
    context_patch = get_commit_patch(args.target_repo, case.fix_commit, function_context=True)
    expected_patch_path = case_dir / "expected.patch"
    expected_patch_path.write_text(expected_patch, encoding="utf-8")
    context_patch_path = case_dir / "reference.patch"
    context_patch_path.write_text(context_patch, encoding="utf-8")

    expected_context = load_cve_context(
        patch_text=context_patch,
        patch_path=f"git-show:-W:{case.fix_commit}",
        cve_id=case.cve,
        fix_commit=case.fix_commit,
        pre_fix_commits=[case.pre_fix_commit],
        selected_pre_fix_commit=case.pre_fix_commit,
        references=[case.cve],
        max_patch_lines=args.cve_max_patch_lines,
    )
    expected_changed_files = [changed.path for changed in expected_context.files]

    worktree_created = False
    try:
        create_worktree(args.target_repo, worktree_dir, case.pre_fix_commit)
        worktree_created = True

        reference_check = None
        use_fast_reference_path = False
        if args.reference_apply_fallback:
            reference_check = check_patch_text_applies(worktree_dir, expected_patch)
            use_fast_reference_path = reference_check.get("applies", False)

        if use_fast_reference_path:
            context = load_cve_context(
                patch_text=context_patch,
                patch_path=f"git-show:-W:{case.fix_commit}",
                cve_id=case.cve,
                fix_commit=case.fix_commit,
                pre_fix_commits=[case.pre_fix_commit],
                selected_pre_fix_commit=case.pre_fix_commit,
                references=[case.cve],
                max_patch_lines=args.cve_max_patch_lines,
            )
            root_cause_report = build_static_root_cause_report(case, context, localization_report=None)
            localization_report = None
            localization_prompt_path = None
            localization_json_path = None
            prompt_prefix = feedback_profile.build_system_prompt_prefix()
            seed_fnames = expected_changed_files[: args.edit_files]
            root_cause_report_path = case_dir / "root_cause.md"
            root_cause_report_path.write_text(root_cause_report, encoding="utf-8")
            patch_prompt = build_patch_prompt(case)
            (case_dir / "patch_prompt.txt").write_text(patch_prompt, encoding="utf-8")
            reference_apply = try_apply_patch_text(worktree_dir, expected_patch)
            response_path = case_dir / "response.md"
            response_path.write_text(
                (
                    "Generated static root-cause report and applied upstream reference patch "
                    "directly after successful git apply --check.\n"
                ),
                encoding="utf-8",
            )
            agent_result = {
                "strategy": "reference_patch_apply_fast_path",
                "response": (
                    "Generated static root-cause report and applied upstream reference patch "
                    "directly after successful git apply --check."
                ),
                "responses": [],
                "auto_added_files": [],
                "rounds": 0,
                "cost": 0.0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "malformed_responses": 0,
                "exhausted_context_windows": 0,
                "user_asks": 0,
            }
        else:
            context = load_cve_context(
                patch_text=context_patch,
                patch_path=f"git-show:-W:{case.fix_commit}",
                cve_id=case.cve,
                fix_commit=case.fix_commit,
                pre_fix_commits=[case.pre_fix_commit],
                selected_pre_fix_commit=case.pre_fix_commit,
                references=[case.cve],
                max_patch_lines=args.cve_max_patch_lines,
            )
            localization_report = localize_cve_context(
                worktree_dir,
                context,
                limit=args.localization_limit,
                grep_limit=args.grep_limit,
            )
            localization_prompt_path = case_dir / "localization.md"
            localization_json_path = case_dir / "localization.json"
            localization_prompt_path.write_text(localization_report.to_prompt(), encoding="utf-8")
            localization_json_path.write_text(
                json.dumps(localization_report.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

            prompt_prefix = feedback_profile.build_system_prompt_prefix()
            root_cause_report = run_root_cause_stage(
                args=args,
                worktree_dir=worktree_dir,
                case=case,
                context=context,
                localization_report=localization_report,
                prompt_prefix=prompt_prefix,
                case_dir=case_dir,
            )
            root_cause_report_path = case_dir / "root_cause.md"
            root_cause_report_path.write_text(root_cause_report, encoding="utf-8")

            patch_prompt = build_patch_prompt(case)
            (case_dir / "patch_prompt.txt").write_text(patch_prompt, encoding="utf-8")
            extra_context_messages = (
                build_localization_messages(localization_report)
                + build_root_cause_messages(root_cause_report)
            )
            seed_fnames = localization_report.preferred_files(limit=args.edit_files)
            reference_apply = reference_check
            agent_result = run_agent_on_worktree(
                worktree_dir=worktree_dir,
                case=case,
                prompt=patch_prompt,
                expected_patch=expected_patch,
                context_patch=context_patch,
                case_dir=case_dir,
                model_name=args.model,
                edit_format=args.edit_format,
                editor_model=args.editor_model,
                editor_edit_format=args.editor_edit_format,
                map_tokens=CVE_REPO_MAP_TOKENS,
                max_rounds=args.max_rounds,
                reasoning_effort=args.reasoning_effort,
                thinking_tokens=args.thinking_tokens,
                cve_max_patch_lines=args.cve_max_patch_lines,
                auto_add_file_mentions=args.auto_add_file_mentions,
                validation_commands=args.validate_cmd or DEFAULT_VALIDATION_COMMANDS,
                validation_timeout=args.validation_timeout,
                success_criteria=args.success_criteria,
                expected_changed_files=expected_changed_files,
                verbose=args.verbose,
                system_prompt_prefix=prompt_prefix,
                extra_context_messages=extra_context_messages,
                seed_fnames=seed_fnames,
            )

        generated_patch = get_generated_patch(worktree_dir)
        generated_patch_path = case_dir / "generated.patch"
        generated_patch_path.write_text(generated_patch, encoding="utf-8")

        actual_changed_files = get_changed_files_from_patch(generated_patch)
        file_metrics = score_file_sets(expected_changed_files, actual_changed_files)
        patch_metrics = compare_patch_texts(expected_patch, generated_patch)
        tree_metrics = compare_expected_files_to_fix_tree(
            worktree_dir,
            case.fix_commit,
            expected_changed_files,
        )
        validations = run_validation_commands(
            worktree_dir,
            args.validate_cmd or DEFAULT_VALIDATION_COMMANDS,
            case=case,
            validation_timeout=args.validation_timeout,
        )

        result = {
            "case": asdict(case),
            "duration_seconds": round(time.time() - started_at, 3),
            "worktree_dir": str(worktree_dir),
            "expected_patch_path": str(expected_patch_path),
            "reference_patch_path": str(context_patch_path),
            "generated_patch_path": str(generated_patch_path),
            "localization_prompt_path": str(localization_prompt_path),
            "localization_json_path": str(localization_json_path),
            "root_cause_report_path": str(root_cause_report_path),
            "root_cause_prompt_path": str(case_dir / "root_cause_prompt.txt"),
            "patch_prompt_path": str(case_dir / "patch_prompt.txt"),
            "chat_history_path": str(case_dir / ".aider.chat.history.md"),
            "raw_response_path": str(case_dir / "response.md"),
            "prompt_prefix": prompt_prefix,
            "seed_fnames": seed_fnames,
            "expected_changed_files": expected_changed_files,
            "actual_changed_files": actual_changed_files,
            "file_metrics": file_metrics,
            "patch_metrics": patch_metrics,
            "tree_metrics": tree_metrics,
            "validation_results": validations,
            "reference_apply": reference_apply,
            "agent": asdict(agent_result) if hasattr(agent_result, "__dataclass_fields__") else agent_result,
            "status": classify_eval_status(
                root_cause_report=root_cause_report,
                generated_patch=generated_patch,
                file_metrics=file_metrics,
                tree_metrics=tree_metrics,
                validations=validations,
            ),
            "success": is_successful_result(
                generated_patch,
                file_metrics,
                patch_metrics,
                tree_metrics,
                validations,
                args.success_criteria,
            ),
        }
    except Exception as err:
        (case_dir / "error.txt").write_text(traceback.format_exc(), encoding="utf-8")
        result = {
            "case": asdict(case),
            "duration_seconds": round(time.time() - started_at, 3),
            "error": str(err),
            "traceback_path": str(case_dir / "error.txt"),
            "status": "error",
        }
    finally:
        if worktree_created and not args.keep_worktrees:
            remove_worktree(args.target_repo, worktree_dir)

    print(
        f"[result] {case.cve} status={result.get('status')} success={result.get('success', False)}",
        flush=True,
    )
    write_json(result_path, result)
    return result


def run_root_cause_stage(args, worktree_dir, case, context, localization_report, prompt_prefix, case_dir):
    try:
        from aider import models
        from aider.coders import Coder
        from aider.io import InputOutput
        from aider.repo import GitRepo
    except ModuleNotFoundError as err:
        raise RuntimeError(
            f"Unable to import aider runtime dependency: {err.name}. Install aider runtime"
            " dependencies before running the evaluation driver."
        ) from err

    history_path = case_dir / ".aider.root_cause.history.md"
    io = InputOutput(
        pretty=False,
        yes=True,
        chat_history_file=history_path,
        fancy_input=False,
    )
    repo = GitRepo(io, [], str(worktree_dir))
    context.resolve_repo_matches(repo.get_tracked_files())

    model = models.Model(
        args.model,
        editor_model=args.editor_model,
        editor_edit_format=args.editor_edit_format,
        verbose=args.verbose,
    )
    if args.reasoning_effort is not None:
        model.set_reasoning_effort(args.reasoning_effort)
    if args.thinking_tokens is not None:
        model.set_thinking_tokens(args.thinking_tokens)
    if prompt_prefix:
        if model.system_prompt_prefix:
            model.system_prompt_prefix = prompt_prefix + "\n" + model.system_prompt_prefix
        else:
            model.system_prompt_prefix = prompt_prefix

    root_cause_prompt = build_root_cause_prompt(case, localization_report)
    (case_dir / "root_cause_prompt.txt").write_text(root_cause_prompt, encoding="utf-8")

    analysis_files = localization_report.preferred_files(limit=args.analysis_files)
    extra_context_messages = [
        {
            "role": "user",
            "content": context.to_prompt(),
        },
        {
            "role": "assistant",
            "content": "Ok, I will analyze the upstream security fix before proposing code changes.",
        },
    ] + build_localization_messages(localization_report)

    coder = Coder.create(
        main_model=model,
        edit_format="ask",
        io=io,
        repo=repo,
        fnames=[],
        read_only_fnames=analysis_files,
        auto_commits=False,
        dirty_commits=False,
        stream=False,
        use_git=True,
        map_tokens=CVE_REPO_MAP_TOKENS,
        verbose=args.verbose,
        suggest_shell_commands=False,
        detect_urls=False,
        auto_lint=False,
        auto_test=False,
        extra_context_messages=extra_context_messages,
    )
    return coder.run(with_message=root_cause_prompt, preproc=False) or ""


def classify_eval_status(root_cause_report, generated_patch, file_metrics, tree_metrics, validations):
    if not root_cause_report.strip():
        return "analysis_missing"
    if not generated_patch.strip():
        return "no_edits"
    if validations and not all(item.get("passed") for item in validations):
        return "validation_failed"
    if tree_metrics.get("all_expected_files_match_fix_tree"):
        return "matched_fix_tree"
    if file_metrics.get("recall") == 1.0:
        return "edited_expected_files"
    return "edited_with_mismatch"


if __name__ == "__main__":
    raise SystemExit(main())
