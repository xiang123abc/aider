import json
from difflib import SequenceMatcher
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path


SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".rs")


@dataclass
class LocalizationCandidate:
    path: str
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    matched_symbols: list[str] = field(default_factory=list)
    snippets: list[str] = field(default_factory=list)

    def add(self, score, reason, symbol=None, snippet=None):
        self.score += score
        if reason not in self.reasons:
            self.reasons.append(reason)
        if symbol and symbol not in self.matched_symbols:
            self.matched_symbols.append(symbol)
        if snippet and snippet not in self.snippets:
            self.snippets.append(snippet)


@dataclass
class LocalizationReport:
    repo_path: str
    exact_matches: list[str] = field(default_factory=list)
    unmatched_upstream_paths: list[str] = field(default_factory=list)
    candidate_symbols: list[str] = field(default_factory=list)
    candidates: list[LocalizationCandidate] = field(default_factory=list)
    strategy_notes: list[str] = field(default_factory=list)

    def candidate_files(self, limit=6):
        return [candidate.path for candidate in self.candidates[:limit]]

    def preferred_files(self, limit=6):
        if self.exact_matches:
            return self.exact_matches[:limit]
        return self.candidate_files(limit=limit)

    def to_prompt(self):
        lines = [
            "Linux target localization report:",
            f"- Repo: {self.repo_path}",
            f"- Exact upstream path matches: {len(self.exact_matches)}",
        ]

        if self.exact_matches:
            lines.append("Exact matches: " + ", ".join(self.exact_matches[:8]))
        if self.unmatched_upstream_paths:
            lines.append(
                "Unmatched upstream paths: " + ", ".join(self.unmatched_upstream_paths[:8])
            )
        if self.candidate_symbols:
            lines.append("Candidate symbols: " + ", ".join(self.candidate_symbols[:12]))
        if self.strategy_notes:
            lines.append("Localization strategy: " + "; ".join(self.strategy_notes))

        if self.candidates:
            lines.append("Top candidate local files:")
            for index, candidate in enumerate(self.candidates[:10], start=1):
                lines.append(
                    f"{index}. {candidate.path} score={candidate.score} reasons="
                    + ", ".join(candidate.reasons[:5])
                )
                if candidate.matched_symbols:
                    lines.append("   symbols: " + ", ".join(candidate.matched_symbols[:6]))
                for snippet in candidate.snippets[:2]:
                    lines.append("   hit: " + snippet)

        return "\n".join(lines)

    def to_dict(self):
        return {
            "repo_path": self.repo_path,
            "exact_matches": self.exact_matches,
            "unmatched_upstream_paths": self.unmatched_upstream_paths,
            "candidate_symbols": self.candidate_symbols,
            "candidates": [asdict(candidate) for candidate in self.candidates],
            "strategy_notes": self.strategy_notes,
        }


GUIDANCE_LIBRARY = {
    "force_patch_output": (
        "Analysis is mandatory, but every repair round must end with concrete code edits."
    ),
    "follow_upstream_files": (
        "Prefer the same touched files, helper boundaries and control-flow placement as the"
        " upstream fix when the local tree still has equivalent code."
    ),
    "avoid_unrelated_files": "Avoid unrelated refactors or edits outside the localized security path.",
    "preserve_error_paths": (
        "Preserve existing kernel-style cleanup ordering, locking and error-path balance."
    ),
    "follow_upstream_shape": (
        "When the local code is structurally close, follow the upstream patch more literally."
    ),
}


@dataclass
class PromptFeedbackProfile:
    total_cases: int = 0
    status_counts: dict[str, int] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)
    history: list[dict] = field(default_factory=list)

    def increment(self, key):
        self.counters[key] = self.counters.get(key, 0) + 1

    def record_result(self, result):
        if result.get("status") == "error":
            return

        self.total_cases += 1

        status = result.get("status", "unknown")
        self.status_counts[status] = self.status_counts.get(status, 0) + 1

        file_metrics = result.get("file_metrics", {})
        patch_metrics = result.get("patch_metrics", {})
        tree_metrics = result.get("tree_metrics", {})
        validations = result.get("validation_results", [])

        if status == "no_edits":
            self.increment("force_patch_output")
        if file_metrics.get("recall", 1.0) < 1.0:
            self.increment("follow_upstream_files")
        if file_metrics.get("unexpected_files"):
            self.increment("avoid_unrelated_files")
        if validations and not all(item.get("passed") for item in validations):
            self.increment("preserve_error_paths")
        if not patch_metrics.get("patch_id_matches") and not tree_metrics.get(
            "all_expected_files_match_fix_tree"
        ):
            self.increment("follow_upstream_shape")

        self.history.append(
            {
                "case": result.get("case", {}).get("cve"),
                "status": status,
                "recall": file_metrics.get("recall"),
                "precision": file_metrics.get("precision"),
                "unexpected_files": file_metrics.get("unexpected_files", []),
            }
        )

    def active_guidance(self):
        items = []
        for key, count in sorted(self.counters.items(), key=lambda item: (-item[1], item[0])):
            message = GUIDANCE_LIBRARY.get(key)
            if count > 0 and message:
                items.append(message)
        return items

    def build_system_prompt_prefix(self):
        guidance = self.active_guidance()
        if not guidance:
            return None

        lines = ["CVE benchmark feedback from earlier repair attempts:"]
        for message in guidance[:5]:
            lines.append(f"- {message}")
        return "\n".join(lines)

    def to_dict(self):
        return {
            "total_cases": self.total_cases,
            "status_counts": self.status_counts,
            "counters": self.counters,
            "history": self.history,
            "active_guidance": self.active_guidance(),
            "system_prompt_prefix": self.build_system_prompt_prefix(),
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            total_cases=data.get("total_cases", 0),
            status_counts=dict(data.get("status_counts", {})),
            counters=dict(data.get("counters", {})),
            history=list(data.get("history", [])),
        )


@dataclass
class PointEdit:
    path: str
    search_lines: list[str] = field(default_factory=list)
    replace_lines: list[str] = field(default_factory=list)
    reason: str | None = None


@dataclass
class PointEditPlan:
    summary: str = ""
    edits: list[PointEdit] = field(default_factory=list)


@dataclass
class PointEditRunResult:
    response: str = ""
    responses: list[str] = field(default_factory=list)
    rounds: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    parse_failures: int = 0
    apply_failures: list[str] = field(default_factory=list)
    strategy: str = "point_edit_json"


def load_feedback_profile(path):
    path = Path(path)
    if not path.exists():
        return PromptFeedbackProfile()
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    return PromptFeedbackProfile.from_dict(data)


def save_feedback_profile(path, profile):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profile.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")


def localize_cve_context(repo_path, cve_context, limit=12, grep_limit=3, tracked_files=None):
    repo_path = Path(repo_path).resolve()
    tracked_files = tracked_files or get_tracked_files(repo_path)

    cve_context.resolve_repo_matches(tracked_files)

    candidates = {}
    strategy_notes = ["exact path and basename matches", "git grep on affected symbols"]

    for changed in cve_context.files:
        if changed.exact_repo_match:
            add_candidate(
                candidates,
                changed.exact_repo_match,
                200,
                "exact-upstream-path",
            )

        for candidate in changed.repo_candidates[:3]:
            add_candidate(candidates, candidate, 70, "same-basename-candidate")

        parent = str(Path(changed.path).parent)
        if parent and parent != ".":
            matching_paths = [
                path
                for path in tracked_files
                if path.startswith(parent + "/") and path.endswith(SOURCE_SUFFIXES)
            ][:3]
            for match in matching_paths:
                add_candidate(candidates, match, 35, "same-subsystem-prefix")

    candidate_symbols = cve_context.candidate_symbols()[:20]
    for symbol in candidate_symbols:
        for path, lineno, text in git_grep_symbol(repo_path, symbol, limit=grep_limit):
            snippet = f"{path}:{lineno}: {text.strip()}"
            add_candidate(
                candidates,
                path,
                55,
                "symbol-hit",
                symbol=symbol,
                snippet=snippet,
            )

    ranked = sorted(candidates.values(), key=lambda item: (-item.score, item.path))
    report = LocalizationReport(
        repo_path=str(repo_path),
        exact_matches=cve_context.exact_matches(),
        unmatched_upstream_paths=cve_context.unmatched_files(),
        candidate_symbols=candidate_symbols,
        candidates=ranked[:limit],
        strategy_notes=strategy_notes,
    )
    return report


def build_root_cause_prompt(case, localization_report):
    return (
        f"You are analyzing {case.cve}.\n"
        f"The current checkout is the vulnerable commit {case.pre_fix_commit} and the upstream"
        f" fixed commit is {case.fix_commit}.\n"
        "First compare the vulnerable logic against the upstream fix already injected into"
        " context.\n"
        "Use the localization report already in chat to focus on the likely local files and"
        " symbols.\n"
        "Write a root-cause report with these sections:\n"
        "1. Vulnerability root cause\n"
        "2. Trigger and attacker-controlled path\n"
        "3. Affected local files/functions\n"
        "4. Security invariant restored by the fix\n"
        "5. Minimal backport strategy for this tree\n"
        "Do not emit a patch in this step."
    )


def build_patch_prompt(case):
    return (
        f"Continue the repair for {case.cve}.\n"
        f"The current checkout is the vulnerable commit {case.pre_fix_commit}.\n"
        "Use the upstream fix context, the localization report and the root-cause report already"
        " in chat.\n"
        "If the local code is structurally close to upstream, keep the same relative placement of"
        " declarations, NULL checks and early returns as the upstream patch.\n"
        "Do not reorder existing statements unless the upstream patch also reorders them.\n"
        "Apply the minimal safe fix directly to the code now.\n"
        "Do not stop at analysis."
    )


def build_point_edit_prompt(case, cve_context, root_cause_report, editable_files, prompt_prefix=None):
    lines = []
    if prompt_prefix:
        lines.append(prompt_prefix)
        lines.append("")

    lines.extend(
        [
            "You are generating targeted code edits for a Linux kernel security fix.",
            f"CVE: {case.cve}",
            f"Target vulnerable commit: {case.pre_fix_commit}",
            f"Upstream fixed commit: {case.fix_commit}",
            "",
            "Return strict JSON only. No markdown fences, no commentary.",
            'Use exactly this schema: {"summary": "...", "edits": [{"path": "...", "search_lines": ["..."], "replace_lines": ["..."], "reason": "..."}]}',
            "",
            "Rules:",
            "- Only edit the provided file paths.",
            "- search_lines must be an exact contiguous block from the current file.",
            "- replace_lines must be the full replacement for that block.",
            "- Keep each edit small and local.",
            "- For insertions, include surrounding unchanged anchor lines in both search_lines and replace_lines.",
            "- Do not reorder unrelated code.",
            "- Preserve exact leading whitespace. Tabs are significant.",
            "- If the local code is structurally close to upstream, preserve the same statement order and placement as the upstream fix.",
            "- If no safe edit can be produced, return an empty edits array.",
            "",
            "Root-cause analysis:",
            root_cause_report.strip(),
            "",
            "Upstream reference patch:",
            cve_context.patch_excerpt(),
            "",
            "Editable files and current contents as JSON line arrays. Copy exact strings from them, including escaped tabs:",
            format_editable_files(editable_files),
        ]
    )
    return "\n".join(lines)


def build_point_edit_retry_prompt(parse_error=None, apply_failures=None):
    lines = [
        "Your previous edit response was not applied successfully.",
        "Return strict JSON only, using the same schema as before.",
    ]
    if parse_error:
        lines.append("JSON parse problem: " + parse_error)
    if apply_failures:
        lines.append("Apply failures:")
        lines.extend(apply_failures)
    lines.append("Try again with smaller, exact search_lines blocks copied from the current file.")
    return "\n".join(lines)


def build_localization_messages(localization_report):
    return [
        {
            "role": "user",
            "content": localization_report.to_prompt(),
        },
        {
            "role": "assistant",
            "content": "Ok, I will prioritize those files and symbols when adapting the fix.",
        },
    ]


def build_root_cause_messages(root_cause_report):
    return [
        {
            "role": "user",
            "content": "Root-cause analysis report:\n\n" + root_cause_report.strip(),
        },
        {
            "role": "assistant",
            "content": "Ok, I will preserve that security invariant while applying the patch.",
        },
    ]


def build_static_root_cause_report(case, cve_context, localization_report=None):
    changed_files = [changed.path for changed in cve_context.files]
    scopes = []
    for changed in cve_context.files:
        scopes.extend(changed.hunk_scopes[:2])
    scopes = scopes[:6]

    lines = [
        f"### {case.cve} Root-Cause Analysis",
        "",
        "---",
        "",
        "#### 1. Vulnerability Root Cause",
        "",
        (
            "The vulnerable behavior is in the code updated by the upstream fix commit "
            f"{case.fix_commit}. Because this fix applies cleanly to the target vulnerable commit "
            f"{case.pre_fix_commit}, the local tree still matches the upstream vulnerable logic at "
            "the affected site."
        ),
        (
            "The root cause is therefore the missing validation, lifetime handling, state check or "
            "cleanup ordering corrected by the upstream patch in the affected function scope."
        ),
        "",
        "#### 2. Trigger and Attacker-Controlled Path",
        "",
        (
            "The trigger follows the same execution path as the upstream vulnerability because the "
            "reference patch applies without conflicts on this target tree."
        ),
        (
            "Any attacker-controlled inputs that reach the affected local function can therefore "
            "exercise the same vulnerable logic until the upstream fix is backported."
        ),
        "",
        "#### 3. Affected Local Files/Functions",
        "",
        f"- Files: {', '.join(changed_files) if changed_files else '(unknown)'}",
    ]

    if scopes:
        lines.append(f"- Likely scopes: {', '.join(scopes)}")
    if localization_report and localization_report.exact_matches:
        lines.append(f"- Exact local matches: {', '.join(localization_report.exact_matches[:6])}")

    lines.extend(
        [
            "",
            "#### 4. Security Invariant Restored by the Fix",
            "",
            (
                "The upstream patch restores the security invariant required at the affected "
                "function boundary. Because the patch applies directly, preserving the same "
                "statement order and helper usage restores the intended invariant in this tree."
            ),
            "",
            "#### 5. Minimal Backport Strategy for This Tree",
            "",
            (
                "Apply the upstream patch as-is to the target tree. This is the minimal and safest "
                "backport because `git apply --check` already confirmed that the vulnerable code "
                "shape matches upstream closely enough for a direct replay."
            ),
        ]
    )

    return "\n".join(lines)


def format_editable_files(editable_files):
    chunks = []
    for path, content in editable_files:
        chunks.append(f"<file path=\"{path}\">")
        chunks.append(json.dumps(content.splitlines(), ensure_ascii=False, indent=2))
        chunks.append("</file>")
    return "\n".join(chunks)


def extract_json_object(text):
    text = text.strip()
    if not text:
        raise ValueError("Empty model response")

    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object found in model response")

    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text[start:], start=start):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : index + 1])

    raise ValueError("Unterminated JSON object in model response")


def parse_point_edit_plan(response_text):
    data = extract_json_object(response_text)
    edits = []
    for item in data.get("edits", []):
        edits.append(
            PointEdit(
                path=item["path"],
                search_lines=normalize_line_array(item.get("search_lines") or item.get("search")),
                replace_lines=normalize_line_array(item.get("replace_lines") or item.get("replace")),
                reason=item.get("reason"),
            )
        )
    return PointEditPlan(summary=data.get("summary", ""), edits=edits)


def normalize_line_array(value):
    if value is None:
        return []
    if isinstance(value, str):
        return value.splitlines()
    if isinstance(value, list):
        return [str(line) for line in value]
    raise ValueError(f"Unsupported line array value: {type(value)}")


def render_lines(lines):
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def normalize_search_variants(lines):
    variants = [lines]

    stripped_plus = [line[1:] if line.startswith("+") else line for line in lines]
    if stripped_plus != lines:
        variants.append(stripped_plus)

    deduped = []
    seen = set()
    for variant in variants:
        key = tuple(variant)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(variant)
    return deduped


def leading_whitespace(line):
    return line[: len(line) - len(line.lstrip(" \t"))]


def find_stripped_match_lines(content, search_lines):
    content_lines = content.splitlines()
    target = [line.lstrip(" \t") for line in search_lines]
    if not target:
        return None

    for start in range(len(content_lines) - len(target) + 1):
        chunk = content_lines[start : start + len(target)]
        if [line.lstrip(" \t") for line in chunk] == target:
            return chunk

    return None


def choose_indent(search_indents, a_start, a_end, a_index, last_indent):
    if a_start < a_end and a_index < len(search_indents):
        return search_indents[a_index]
    if a_start > 0:
        return search_indents[a_start - 1]
    if a_end < len(search_indents):
        return search_indents[a_end]
    return last_indent


def reindent_replace_lines(search_lines, replace_lines, matched_lines):
    search_stripped = [line.lstrip(" \t") for line in search_lines]
    replace_stripped = [line.lstrip(" \t") for line in replace_lines]
    search_indents = [leading_whitespace(line) for line in matched_lines]

    rebuilt = [""] * len(replace_lines)
    matcher = SequenceMatcher(a=search_stripped, b=replace_stripped)
    last_indent = search_indents[0] if search_indents else ""

    for tag, a_start, a_end, b_start, b_end in matcher.get_opcodes():
        if tag == "equal":
            for offset, b_index in enumerate(range(b_start, b_end)):
                a_index = a_start + offset
                indent = search_indents[a_index] if a_index < len(search_indents) else last_indent
                rebuilt[b_index] = indent + replace_stripped[b_index] if replace_stripped[b_index] else ""
                last_indent = indent
            continue

        for offset, b_index in enumerate(range(b_start, b_end)):
            a_index = min(a_start + offset, max(a_end - 1, a_start))
            indent = choose_indent(search_indents, a_start, a_end, a_index, last_indent)
            rebuilt[b_index] = indent + replace_stripped[b_index] if replace_stripped[b_index] else ""
            last_indent = indent

    for index, line in enumerate(rebuilt):
        if line == "" and replace_lines[index].strip():
            rebuilt[index] = replace_lines[index]

    return rebuilt


def apply_point_edit_plan(worktree_dir, plan, allowed_paths):
    from aider.coders.editblock_coder import DEFAULT_FENCE, do_replace, find_similar_lines

    worktree_dir = Path(worktree_dir).resolve()
    allowed = set(allowed_paths)
    file_cache = {}
    modified_paths = set()
    failures = []

    for edit in plan.edits:
        if edit.path not in allowed:
            failures.append(f"{edit.path}: path is not in the allowed editable set")
            continue

        full_path = worktree_dir / edit.path
        if edit.path not in file_cache:
            file_cache[edit.path] = full_path.read_text(encoding="utf-8", errors="replace")

        before_text = render_lines(edit.search_lines)
        after_text = render_lines(edit.replace_lines)
        new_content = None
        tried_variants = []
        for variant in normalize_search_variants(edit.search_lines):
            variant_text = render_lines(variant)
            tried_variants.append(variant_text)
            new_content = do_replace(
                full_path,
                file_cache[edit.path],
                variant_text,
                after_text,
                fence=DEFAULT_FENCE,
            )
            if new_content is not None:
                break

        if new_content is None:
            similar = ""
            for variant_text in tried_variants or [before_text]:
                similar = find_similar_lines(variant_text, file_cache[edit.path])
                if similar:
                    new_content = do_replace(
                        full_path,
                        file_cache[edit.path],
                        similar + "\n",
                        after_text,
                        fence=DEFAULT_FENCE,
                    )
                    if new_content is not None:
                        break

        if new_content is None:
            matched_lines = find_stripped_match_lines(file_cache[edit.path], edit.search_lines)
            if matched_lines:
                adjusted_replace_lines = reindent_replace_lines(
                    edit.search_lines,
                    edit.replace_lines,
                    matched_lines,
                )
                new_content = do_replace(
                    full_path,
                    file_cache[edit.path],
                    render_lines(matched_lines),
                    render_lines(adjusted_replace_lines),
                    fence=DEFAULT_FENCE,
                )
                similar = "\n".join(matched_lines)

        if new_content is None:
            message = f"{edit.path}: search_lines did not match"
            if similar:
                message += "\nClosest match:\n" + similar
            failures.append(message)
            continue

        file_cache[edit.path] = new_content
        modified_paths.add(edit.path)

    for rel_path in modified_paths:
        (worktree_dir / rel_path).write_text(file_cache[rel_path], encoding="utf-8")

    return {
        "modified_paths": sorted(modified_paths),
        "failures": failures,
    }


def add_candidate(candidates, path, score, reason, symbol=None, snippet=None):
    candidate = candidates.setdefault(path, LocalizationCandidate(path=path))
    candidate.add(score, reason, symbol=symbol, snippet=snippet)


def get_tracked_files(repo_path):
    output = run_git(repo_path, ["ls-files"]).stdout
    return [line.strip() for line in output.splitlines() if line.strip()]


def git_grep_symbol(repo_path, symbol, limit=3):
    result = run_git(
        repo_path,
        ["grep", "-n", "-I", "-F", symbol, "--"],
        check=False,
    )
    if result.returncode != 0:
        return []

    hits = []
    for line in result.stdout.splitlines():
        if len(hits) >= limit:
            break

        pieces = line.split(":", 2)
        if len(pieces) != 3:
            continue

        path, lineno, text = pieces
        if not path.endswith(SOURCE_SUFFIXES):
            continue

        hits.append((path, lineno, text))

    return hits


def run_git(repo_path, args, check=True):
    cmd = ["git", "-C", str(Path(repo_path).resolve())] + list(args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        errors="replace",
        check=check,
    )
