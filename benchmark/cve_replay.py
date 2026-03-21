#!/usr/bin/env python3

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aider.cve import (
    load_cve_context,
    load_cve_dataset,
    parse_patch_files,
    select_cve_dataset_entry,
)

DEFAULT_OUTPUT_DIR = Path(os.environ.get("AIDER_CVE_REPLAY_DIR", "tmp.cve-replays"))
DEFAULT_TARGET_REPO = "/root/linux"
DEFAULT_VALIDATION_COMMANDS = ["git diff --check"]
CVE_REPO_MAP_TOKENS = 0


@dataclass
class ReplayCase:
    dataset_index: int
    pre_fix_index: int
    cve: str
    fix_commit: str
    pre_fix_commit: str


@dataclass
class AgentReplayResult:
    response: str = ""
    responses: list[str] = field(default_factory=list)
    auto_added_files: list[list[str]] = field(default_factory=list)
    rounds: int = 0
    cost: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    malformed_responses: int = 0
    exhausted_context_windows: int = 0
    user_asks: int = 0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Replay CVE dataset cases against a target git repository using aider."
    )
    parser.add_argument(
        "run_name",
        nargs="?",
        default="cve-replay",
        help="Name suffix for the output run directory",
    )
    parser.add_argument(
        "--dataset",
        default="cve_fix_dataset.json",
        help="Path to the CVE dataset JSON file",
    )
    parser.add_argument(
        "--target-repo",
        "--rootpath",
        default=DEFAULT_TARGET_REPO,
        dest="target_repo",
        help="Path to the target git repository that contains the dataset commits",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory that stores replay runs and artifacts",
    )
    parser.add_argument(
        "--model",
        required=True,
        help="Main model name passed to aider",
    )
    parser.add_argument(
        "--edit-format",
        default="cve",
        help="Aider edit format used for replay (default: cve)",
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
        help="Select a specific vulnerable pre-fix commit to replay",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of replay cases to run",
    )
    parser.add_argument(
        "--max-pre-fix-per-case",
        type=int,
        default=None,
        help="Limit how many pre-fix commits are expanded per dataset entry",
    )
    parser.add_argument(
        "--map-tokens",
        type=int,
        default=4096,
        help="Repo-map token budget used during replay",
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
        help="Maximum agent rounds per replay case",
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
        help="Condition that marks a replay case as successful",
    )
    parser.add_argument(
        "--validate-cmd",
        action="append",
        default=[],
        help="Validation command to run inside each replay worktree. Can be repeated.",
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
        help="Keep worktree directories after each replay case",
    )
    parser.add_argument(
        "--auto-add-file-mentions",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Auto-add file mentions from assistant replies between replay rounds",
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

    dataset_entries = load_cve_dataset(args.dataset)
    cases = expand_dataset_cases(
        dataset_entries,
        selectors=args.case,
        max_pre_fix_per_case=args.max_pre_fix_per_case,
        limit=args.limit,
    )
    if args.commit_id:
        cases = [
            case
            for case in cases
            if case.pre_fix_commit.startswith(args.commit_id)
            or case.fix_commit.startswith(args.commit_id)
        ]

    if not cases:
        print("No replay cases selected.")
        return 1

    run_manifest = {
        "created_at": dt.datetime.now(dt.UTC).isoformat(),
        "dataset": str(Path(args.dataset).resolve()),
        "target_repo": str(Path(args.target_repo).resolve()),
        "model": args.model,
        "edit_format": args.edit_format,
        "cases": [asdict(case) for case in cases],
        "aider_repo": describe_repo_state(Path.cwd()),
        "target_repo_state": describe_repo_state(Path(args.target_repo)),
    }
    write_json(run_dir / "run_manifest.json", run_manifest)

    results = []
    for case in cases:
        result = run_replay_case(args, run_dir, case)
        results.append(result)
        append_jsonl(run_dir / "results.jsonl", result)
        write_json(run_dir / "summary.json", summarize_replay_results(results))

    return 0


def create_run_dir(output_root, run_name):
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y-%m-%d-%H-%M-%S")
    slug = sanitize_slug(run_name)
    return output_root / f"{timestamp}--{slug}"


def expand_dataset_cases(entries, selectors=None, max_pre_fix_per_case=None, limit=None):
    selected = list(select_dataset_entries(entries, selectors))
    cases = []

    for dataset_index, entry in selected:
        commits = list(entry.pre_fix_commits)
        if max_pre_fix_per_case is not None:
            commits = commits[:max_pre_fix_per_case]

        for pre_fix_index, pre_fix_commit in enumerate(commits):
            cases.append(
                ReplayCase(
                    dataset_index=dataset_index,
                    pre_fix_index=pre_fix_index,
                    cve=entry.cve,
                    fix_commit=entry.fix_commit,
                    pre_fix_commit=pre_fix_commit,
                )
            )

    if limit is not None:
        cases = cases[:limit]

    return cases


def select_dataset_entries(entries, selectors=None):
    indexed_entries = list(enumerate(entries))
    if not selectors:
        return indexed_entries

    selected = []
    seen = set()
    for selector in selectors:
        entry = select_cve_dataset_entry(entries, selector)
        key = (entry.cve, entry.fix_commit)
        if key in seen:
            continue
        seen.add(key)
        for dataset_index, indexed_entry in indexed_entries:
            if indexed_entry.cve == entry.cve and indexed_entry.fix_commit == entry.fix_commit:
                selected.append((dataset_index, indexed_entry))
                break
    return selected


def run_replay_case(args, run_dir, case):
    case_slug = make_case_slug(case)
    case_dir = run_dir / "cases" / case_slug
    worktree_dir = run_dir / "worktrees" / case_slug
    result_path = case_dir / "result.json"

    case_dir.mkdir(parents=True, exist_ok=True)
    if args.resume and result_path.exists():
        return json.loads(result_path.read_text())

    print(
        f"[replay] {case.cve} pre_fix={case.pre_fix_commit[:12]} fix={case.fix_commit[:12]}",
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

        prompt = build_replay_prompt(case)
        (case_dir / "prompt.txt").write_text(prompt, encoding="utf-8")

        agent_result = run_agent_on_worktree(
            worktree_dir=worktree_dir,
            case=case,
            prompt=prompt,
            expected_patch=expected_patch,
            context_patch=context_patch,
            case_dir=case_dir,
            model_name=args.model,
            edit_format=args.edit_format,
            editor_model=args.editor_model,
            editor_edit_format=args.editor_edit_format,
            map_tokens=args.map_tokens,
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
            "prompt_path": str(case_dir / "prompt.txt"),
            "chat_history_path": str(case_dir / ".aider.chat.history.md"),
            "raw_response_path": str(case_dir / "response.md"),
            "expected_changed_files": expected_changed_files,
            "actual_changed_files": actual_changed_files,
            "file_metrics": file_metrics,
            "patch_metrics": patch_metrics,
            "tree_metrics": tree_metrics,
            "validation_results": validations,
            "agent": asdict(agent_result),
            "status": classify_case_status(generated_patch, file_metrics, tree_metrics, validations),
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


def run_agent_on_worktree(
    worktree_dir,
    case,
    prompt,
    expected_patch,
    context_patch,
    case_dir,
    model_name,
    edit_format,
    editor_model,
    editor_edit_format,
    map_tokens,
    max_rounds,
    reasoning_effort,
    thinking_tokens,
    cve_max_patch_lines,
    auto_add_file_mentions,
    validation_commands,
    validation_timeout,
    success_criteria,
    expected_changed_files,
    verbose,
    system_prompt_prefix=None,
    extra_context_messages=None,
    seed_fnames=None,
):
    try:
        from aider import models
        from aider.coders import Coder
        from aider.io import InputOutput
        from aider.repo import GitRepo
    except ModuleNotFoundError as err:
        raise RuntimeError(
            f"Unable to import aider runtime dependency: {err.name}. Install aider runtime"
            " dependencies before running the replay executor."
        ) from err

    response_path = case_dir / "response.md"
    history_path = case_dir / ".aider.chat.history.md"

    io = InputOutput(
        pretty=False,
        yes=True,
        chat_history_file=history_path,
        fancy_input=False,
    )
    repo = GitRepo(io, [], str(worktree_dir))
    context = load_cve_context(
        patch_text=context_patch,
        patch_path=f"git-show:-W:{case.fix_commit}",
        cve_id=case.cve,
        fix_commit=case.fix_commit,
        pre_fix_commits=[case.pre_fix_commit],
        selected_pre_fix_commit=case.pre_fix_commit,
        references=[case.cve],
        repo=repo,
        max_patch_lines=cve_max_patch_lines,
    )

    main_model = models.Model(
        model_name,
        editor_model=editor_model,
        editor_edit_format=editor_edit_format,
        verbose=verbose,
    )
    if reasoning_effort is not None:
        main_model.set_reasoning_effort(reasoning_effort)
    if thinking_tokens is not None:
        main_model.set_thinking_tokens(thinking_tokens)
    if system_prompt_prefix:
        if main_model.system_prompt_prefix:
            main_model.system_prompt_prefix = (
                system_prompt_prefix + "\n" + main_model.system_prompt_prefix
            )
        else:
            main_model.system_prompt_prefix = system_prompt_prefix

    result = AgentReplayResult()
    effective_map_tokens = CVE_REPO_MAP_TOKENS
    with pushd(worktree_dir):
        coder = Coder.create(
            main_model=main_model,
            edit_format=edit_format,
            io=io,
            repo=repo,
            fnames=seed_fnames or [],
            auto_commits=False,
            dirty_commits=False,
            stream=False,
            use_git=True,
            map_tokens=effective_map_tokens,
            verbose=verbose,
            suggest_shell_commands=False,
            detect_urls=False,
            auto_lint=False,
            auto_test=False,
            cve_context=context,
            cve_auto_add=True,
            extra_context_messages=extra_context_messages,
        )

        current_message = prompt
        for round_index in range(max_rounds):
            response = coder.run(with_message=current_message, preproc=False) or ""
            result.response = response
            result.responses.append(response)
            result.rounds = round_index + 1
            response_path.write_text(
                "\n\n".join(
                    [
                        f"## Round {index + 1}\n\n{reply}"
                        for index, reply in enumerate(result.responses)
                    ]
                ),
                encoding="utf-8",
            )

            generated_patch = get_generated_patch(worktree_dir)
            if generated_patch.strip():
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
                    validation_commands,
                    case=case,
                    validation_timeout=validation_timeout,
                )

                if is_successful_result(
                    generated_patch,
                    file_metrics,
                    patch_metrics,
                    tree_metrics,
                    validations,
                    success_criteria,
                ):
                    break

                current_message = build_validation_feedback_prompt(
                    case,
                    success_criteria,
                    file_metrics,
                    patch_metrics,
                    tree_metrics,
                    validations,
                )
                continue

            if not auto_add_file_mentions:
                current_message = build_no_edit_feedback_prompt(case, expected_changed_files)
                continue

            existing = set(coder.get_inchat_relative_files())
            mentioned = sorted(coder.get_file_mentions(response, ignore_current=True))
            new_files = [
                rel_fname
                for rel_fname in mentioned
                if rel_fname not in existing and (worktree_dir / rel_fname).exists()
            ]
            if not new_files:
                current_message = build_no_edit_feedback_prompt(case, expected_changed_files)
                continue

            for rel_fname in new_files:
                coder.add_rel_fname(rel_fname)
            result.auto_added_files.append(new_files)
            current_message = build_followup_prompt(case, new_files)
            continue

        result.cost = coder.total_cost
        result.prompt_tokens = coder.total_tokens_sent
        result.completion_tokens = coder.total_tokens_received
        result.malformed_responses = coder.num_malformed_responses
        result.exhausted_context_windows = coder.num_exhausted_context_windows
        result.user_asks = io.num_user_asks

    return result


def build_replay_prompt(case):
    return (
        f"You are working on CVE replay task {case.cve}.\n"
        f"The current checkout is the vulnerable pre-fix commit {case.pre_fix_commit}.\n"
        f"Use the injected upstream fix context to understand the vulnerability root cause and"
        " adapt the equivalent minimal safe fix to this tree.\n"
        "Modify the code directly.\n"
        "If you truly need additional existing files, mention their exact paths so they can be"
        " added automatically."
    )


def build_followup_prompt(case, new_files):
    files = ", ".join(new_files)
    return (
        f"Continue CVE replay task {case.cve}. The additional files are now available: {files}.\n"
        "Proceed with the code changes and apply the fix directly."
    )


def build_no_edit_feedback_prompt(case, expected_changed_files):
    files = ", ".join(expected_changed_files) if expected_changed_files else "(unknown)"
    return (
        f"You did not apply any patch for CVE replay task {case.cve}.\n"
        f"The benchmark expects edits in files such as: {files}.\n"
        "Modify the code directly now and return a valid patch."
    )


def build_validation_feedback_prompt(
    case,
    success_criteria,
    file_metrics,
    patch_metrics,
    tree_metrics,
    validations,
):
    failed_commands = [item for item in validations if not item.get("passed")]
    lines = [
        f"The previous attempt for {case.cve} is not accepted yet.",
        f"Success criteria: {success_criteria}.",
        f"Changed-file recall: {file_metrics.get('recall')}.",
        f"Changed-file precision: {file_metrics.get('precision')}.",
        f"Patch-id matches expected: {patch_metrics.get('patch_id_matches')}.",
        "Expected files match fix tree: "
        f"{tree_metrics.get('all_expected_files_match_fix_tree')}.",
        "Re-read the upstream patch already provided in context and follow its structure more"
        " literally when the local code permits.",
    ]
    if failed_commands:
        lines.append("Validation commands failed:")
        for item in failed_commands:
            lines.append(f"- {item['command']}")
            stdout = (item.get("stdout") or "").strip()
            stderr = (item.get("stderr") or "").strip()
            if stdout:
                lines.append(stdout[:800])
            if stderr:
                lines.append(stderr[:800])
    lines.append("Adjust the existing changes and apply a corrected patch now.")
    return "\n".join(lines)


def classify_case_status(generated_patch, file_metrics, tree_metrics, validations):
    if not generated_patch.strip():
        return "no_edits"
    if not all_validation_commands_passed(validations):
        return "validation_failed"
    if tree_metrics.get("all_expected_files_match_fix_tree"):
        return "matched_fix_tree"
    if file_metrics.get("recall") == 1.0:
        return "edited_expected_files"
    return "edited_with_mismatch"


def describe_repo_state(repo_path):
    repo_path = Path(repo_path)
    try:
        head = run_git(repo_path, ["rev-parse", "HEAD"]).stdout.strip()
        dirty = bool(run_git(repo_path, ["status", "--short"], check=False).stdout.strip())
        return {"path": str(repo_path.resolve()), "head": head, "dirty": dirty}
    except Exception as err:
        return {"path": str(repo_path), "error": str(err)}


def create_worktree(repo_path, worktree_dir, commit):
    worktree_dir = Path(worktree_dir)
    worktree_dir.parent.mkdir(parents=True, exist_ok=True)
    if worktree_dir.exists():
        shutil.rmtree(worktree_dir, ignore_errors=True)
    run_git(repo_path, ["worktree", "prune"], check=False)
    run_git(repo_path, ["worktree", "add", "--detach", str(worktree_dir), commit])


def remove_worktree(repo_path, worktree_dir):
    worktree_dir = Path(worktree_dir)
    try:
        run_git(repo_path, ["worktree", "remove", "--force", str(worktree_dir)], check=False)
    finally:
        shutil.rmtree(worktree_dir, ignore_errors=True)


def get_commit_patch(repo_path, commit, function_context=False):
    if function_context:
        return run_git(
            repo_path,
            ["show", "--patch", "--stat=0", "--format=email", "-W", commit],
        ).stdout
    return run_git(repo_path, ["format-patch", "-1", "--stdout", commit]).stdout


def get_generated_patch(worktree_dir):
    return run_git(worktree_dir, ["diff", "--binary", "HEAD"], check=False).stdout


def try_apply_patch_text(worktree_dir, patch_text):
    check = check_patch_text_applies(worktree_dir, patch_text)
    if not check["applies"]:
        return {
            "applied": False,
            "check_returncode": check["check_returncode"],
            "stdout": check["stdout"],
            "stderr": check["stderr"],
        }

    apply = subprocess.run(
        ["git", "-C", str(Path(worktree_dir).resolve()), "apply", "--whitespace=nowarn", "-"],
        input=patch_text,
        text=True,
        capture_output=True,
        check=False,
    )
    return {
        "applied": apply.returncode == 0,
        "check_returncode": check["check_returncode"],
        "apply_returncode": apply.returncode,
        "stdout": apply.stdout,
        "stderr": apply.stderr,
    }


def check_patch_text_applies(worktree_dir, patch_text):
    check = subprocess.run(
        ["git", "-C", str(Path(worktree_dir).resolve()), "apply", "--check", "--whitespace=nowarn", "-"],
        input=patch_text,
        text=True,
        capture_output=True,
        check=False,
    )
    return {
        "applies": check.returncode == 0,
        "check_returncode": check.returncode,
        "stdout": check.stdout,
        "stderr": check.stderr,
    }


def get_changed_files_from_patch(patch_text):
    files, _patch_format = parse_patch_files(patch_text)
    return [changed.path for changed in files]


def score_file_sets(expected_files, actual_files):
    expected = set(expected_files)
    actual = set(actual_files)

    intersection = expected & actual
    precision = len(intersection) / len(actual) if actual else 0.0
    recall = len(intersection) / len(expected) if expected else 1.0
    if precision + recall:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0.0

    return {
        "expected_count": len(expected),
        "actual_count": len(actual),
        "intersection_count": len(intersection),
        "missing_expected_files": sorted(expected - actual),
        "unexpected_files": sorted(actual - expected),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def compare_patch_texts(expected_patch, generated_patch):
    expected_patch_id = compute_patch_id(expected_patch)
    generated_patch_id = compute_patch_id(generated_patch)
    return {
        "expected_patch_id": expected_patch_id,
        "generated_patch_id": generated_patch_id,
        "patch_id_matches": bool(expected_patch_id and expected_patch_id == generated_patch_id),
        "generated_patch_nonempty": bool(generated_patch.strip()),
    }


def compute_patch_id(patch_text):
    if not patch_text.strip():
        return None
    result = subprocess.run(
        ["git", "patch-id", "--stable"],
        input=patch_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return result.stdout.split()[0]


def compare_expected_files_to_fix_tree(worktree_dir, fix_commit, expected_files):
    comparisons = []
    for rel_fname in expected_files:
        current_path = Path(worktree_dir) / rel_fname
        expected_blob = get_commit_file(worktree_dir, fix_commit, rel_fname)
        expected_exists = expected_blob is not None
        current_exists = current_path.exists()

        if expected_exists and current_exists:
            current_content = current_path.read_bytes()
            matches = current_content == expected_blob
        else:
            matches = expected_exists == current_exists

        comparisons.append(
            {
                "path": rel_fname,
                "expected_exists": expected_exists,
                "current_exists": current_exists,
                "matches_fix_tree": matches,
            }
        )

    all_match = all(item["matches_fix_tree"] for item in comparisons) if comparisons else False
    return {
        "all_expected_files_match_fix_tree": all_match,
        "matched_expected_files": sum(1 for item in comparisons if item["matches_fix_tree"]),
        "expected_file_count": len(comparisons),
        "file_comparisons": comparisons,
    }


def get_commit_file(repo_or_worktree, commit, rel_fname):
    result = run_git(
        repo_or_worktree,
        ["show", f"{commit}:{rel_fname}"],
        check=False,
        text=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def run_validation_commands(worktree_dir, commands, case, validation_timeout):
    env = os.environ.copy()
    env.update(
        {
            "CVE_ID": case.cve,
            "FIX_COMMIT": case.fix_commit,
            "PRE_FIX_COMMIT": case.pre_fix_commit,
            "WORKTREE": str(Path(worktree_dir).resolve()),
        }
    )

    results = []
    for command in commands:
        try:
            completed = subprocess.run(
                command,
                shell=True,
                cwd=worktree_dir,
                env=env,
                text=True,
                capture_output=True,
                timeout=validation_timeout,
                check=False,
            )
            results.append(
                {
                    "command": command,
                    "returncode": completed.returncode,
                    "passed": completed.returncode == 0,
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                }
            )
        except subprocess.TimeoutExpired as err:
            results.append(
                {
                    "command": command,
                    "returncode": None,
                    "passed": False,
                    "timeout": True,
                    "stdout": err.stdout.decode() if isinstance(err.stdout, bytes) else err.stdout,
                    "stderr": err.stderr.decode() if isinstance(err.stderr, bytes) else err.stderr,
                }
            )
    return results


def all_validation_commands_passed(validations):
    return all(item.get("passed") for item in validations)


def summarize_replay_results(results):
    total = len(results)
    completed = [result for result in results if result.get("status") != "error"]
    with_edits = [
        result for result in completed if result.get("patch_metrics", {}).get("generated_patch_nonempty")
    ]
    matched_fix_tree = [
        result
        for result in completed
        if result.get("tree_metrics", {}).get("all_expected_files_match_fix_tree")
    ]
    validation_passed = [
        result
        for result in completed
        if all_validation_commands_passed(result.get("validation_results", []))
    ]

    avg_recall = average_metric(results, ("file_metrics", "recall"))
    avg_precision = average_metric(results, ("file_metrics", "precision"))

    return {
        "total_cases": total,
        "completed_cases": len(completed),
        "error_cases": total - len(completed),
        "cases_with_edits": len(with_edits),
        "cases_matching_fix_tree": len(matched_fix_tree),
        "cases_with_all_validations_passing": len(validation_passed),
        "successful_cases": sum(1 for result in completed if result.get("success")),
        "average_changed_file_recall": round(avg_recall, 4),
        "average_changed_file_precision": round(avg_precision, 4),
        "status_counts": count_statuses(results),
    }


def average_metric(results, path):
    values = []
    for result in results:
        current = result
        for key in path:
            current = current.get(key, {})
        if isinstance(current, (float, int)):
            values.append(float(current))
    if not values:
        return 0.0
    return sum(values) / len(values)


def count_statuses(results):
    counts = {}
    for result in results:
        status = result.get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def append_jsonl(path, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False))
        fh.write("\n")


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def make_case_slug(case):
    return (
        f"{case.dataset_index:03d}-"
        f"{sanitize_slug(case.cve)}-"
        f"pre{case.pre_fix_index:02d}-"
        f"{case.pre_fix_commit[:12]}"
    )


def sanitize_slug(value):
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-") or "case"


def run_git(repo_or_cwd, args, check=True, text=True):
    cmd = ["git", "-C", str(Path(repo_or_cwd).resolve())] + list(args)
    return subprocess.run(
        cmd,
        check=check,
        capture_output=True,
        text=text,
    )


def is_successful_result(
    generated_patch,
    file_metrics,
    patch_metrics,
    tree_metrics,
    validations,
    success_criteria,
):
    if not generated_patch.strip():
        return False

    if not all_validation_commands_passed(validations):
        return False

    if success_criteria == "validation":
        return True
    if success_criteria == "expected-files":
        return file_metrics.get("recall") == 1.0
    if success_criteria == "patch-id":
        return bool(patch_metrics.get("patch_id_matches"))
    if success_criteria == "fix-tree":
        return bool(tree_metrics.get("all_expected_files_match_fix_tree"))
    if success_criteria == "patch-id-or-fix-tree":
        return bool(
            patch_metrics.get("patch_id_matches")
            or tree_metrics.get("all_expected_files_match_fix_tree")
        )

    raise ValueError(f"Unknown success criteria: {success_criteria}")


@contextmanager
def pushd(path):
    cwd = Path.cwd()
    os.chdir(Path(path).resolve())
    try:
        yield
    finally:
        os.chdir(cwd)


if __name__ == "__main__":
    sys.exit(main())
