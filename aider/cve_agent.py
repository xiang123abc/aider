import json
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
