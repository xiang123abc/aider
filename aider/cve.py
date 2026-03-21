import json
from dataclasses import dataclass, field
from pathlib import Path
import re
import subprocess


SUBJECT_RE = re.compile(r"^Subject:\s*(?:\[[^\]]+\]\s*)?(.*\S)\s*$")
DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+?)\s*$")
HUNK_SCOPE_RE = re.compile(r"^@@(?: .*?)@@(?:\s*(.*))?$")
APPLY_PATCH_ACTION_RE = re.compile(r"^\*\*\* (Update|Add|Delete) File: (.+?)\s*$")
IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
COMMIT_ID_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


@dataclass
class CVEChangedFile:
    path: str
    change_type: str = "update"
    old_path: str | None = None
    new_path: str | None = None
    added_lines: int = 0
    removed_lines: int = 0
    hunk_scopes: list[str] = field(default_factory=list)
    exact_repo_match: str | None = None
    repo_candidates: list[str] = field(default_factory=list)

    def summary(self):
        delta = f"+{self.added_lines}/-{self.removed_lines}"
        summary = f"{self.path} [{self.change_type}, {delta}]"
        if self.exact_repo_match:
            summary += f" -> exact repo match: {self.exact_repo_match}"
        elif self.repo_candidates:
            summary += " -> candidate matches: " + ", ".join(self.repo_candidates[:3])
        else:
            summary += " -> no exact repo match"
        return summary

    def scope_identifiers(self):
        identifiers = []
        for scope in self.hunk_scopes:
            identifiers.extend(extract_scope_identifiers(scope))
        return dedupe(identifiers)


@dataclass
class CVEDatasetEntry:
    cve: str
    fix_commit: str
    pre_fix_commits: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data):
        return cls(
            cve=data["cve"],
            fix_commit=data["fix_commit"],
            pre_fix_commits=list(data.get("pre_fix_commits", [])),
        )


@dataclass
class CVEContext:
    description: str | None = None
    references: list[str] = field(default_factory=list)
    cve_id: str | None = None
    fix_commit: str | None = None
    pre_fix_commits: list[str] = field(default_factory=list)
    selected_pre_fix_commit: str | None = None
    patch_text: str = ""
    patch_path: str | None = None
    patch_subject: str | None = None
    files: list[CVEChangedFile] = field(default_factory=list)
    patch_format: str = "unknown"
    max_patch_lines: int = 400

    @classmethod
    def from_patch_text(
        cls,
        patch_text,
        patch_path=None,
        description=None,
        references=None,
        cve_id=None,
        fix_commit=None,
        pre_fix_commits=None,
        selected_pre_fix_commit=None,
        max_patch_lines=400,
    ):
        patch_subject = extract_patch_subject(patch_text)
        files, patch_format = parse_patch_files(patch_text)
        return cls(
            description=description.strip() if description else None,
            references=list(references or []),
            cve_id=cve_id,
            fix_commit=fix_commit,
            pre_fix_commits=list(pre_fix_commits or []),
            selected_pre_fix_commit=selected_pre_fix_commit,
            patch_text=patch_text,
            patch_path=str(patch_path) if patch_path else None,
            patch_subject=patch_subject,
            files=files,
            patch_format=patch_format,
            max_patch_lines=max_patch_lines,
        )

    def resolve_repo_matches(self, tracked_files, candidate_limit=5):
        tracked_files = [normalize_repo_path(path) for path in tracked_files]
        tracked_set = set(tracked_files)
        basename_index = {}
        for path in tracked_files:
            basename_index.setdefault(Path(path).name, []).append(path)

        for changed in self.files:
            changed.exact_repo_match = None
            changed.repo_candidates = []

            normalized = normalize_repo_path(changed.path)
            if normalized in tracked_set:
                changed.exact_repo_match = normalized
                continue

            basename = Path(normalized).name
            if not basename:
                continue

            candidates = sorted(basename_index.get(basename, []))
            changed.repo_candidates = candidates[:candidate_limit]

    def exact_matches(self):
        return [changed.exact_repo_match for changed in self.files if changed.exact_repo_match]

    def unmatched_files(self):
        return [changed.path for changed in self.files if not changed.exact_repo_match]

    def patch_excerpt(self):
        lines = self.patch_text.rstrip("\n").splitlines()
        if len(lines) <= self.max_patch_lines:
            return "\n".join(lines)

        head_count = max(1, self.max_patch_lines // 2)
        tail_count = max(1, self.max_patch_lines - head_count - 1)
        excerpt = lines[:head_count]
        excerpt.append(f"... [{len(lines) - head_count - tail_count} lines omitted] ...")
        excerpt.extend(lines[-tail_count:])
        return "\n".join(excerpt)

    def summary_lines(self):
        lines = ["CVE context loaded."]
        if self.cve_id:
            lines.append(f"CVE: {self.cve_id}")
        if self.fix_commit:
            lines.append(f"Fix commit: {self.fix_commit}")
        if self.pre_fix_commits:
            lines.append(f"Pre-fix commits: {len(self.pre_fix_commits)}")
        if self.selected_pre_fix_commit:
            lines.append(f"Selected pre-fix commit: {self.selected_pre_fix_commit}")
        if self.patch_path:
            lines.append(f"Patch file: {self.patch_path}")
        if self.patch_subject:
            lines.append(f"Patch subject: {self.patch_subject}")
        if self.description:
            lines.append(f"Description: {self.description}")
        if self.references:
            lines.append("References: " + ", ".join(self.references))
        lines.append(f"Patch format: {self.patch_format}")
        lines.append(f"Changed files: {len(self.files)}")
        exact_matches = self.exact_matches()
        lines.append(f"Exact repo matches: {len(exact_matches)}")
        unmatched = self.unmatched_files()
        if unmatched:
            lines.append("Files without exact repo match: " + ", ".join(unmatched[:5]))
        for changed in self.files[:8]:
            lines.append(f"- {changed.summary()}")
        return lines

    def candidate_symbols(self):
        symbols = []
        for changed in self.files:
            symbols.extend(changed.scope_identifiers())
        return dedupe(symbols)

    def to_prompt(self):
        lines = [
            "I am adapting an upstream CVE or security fix to this repository.",
            "Use this context to infer the vulnerability root cause, the security invariant being restored, and the safest equivalent fix for the current tree.",
            "Do not blindly replay the upstream patch line-for-line if the local code has drifted.",
            "Prefer the minimal reviewable fix that preserves the same security property in this code base.",
        ]

        if self.description:
            lines.append(f"Security issue description: {self.description}")

        if self.references:
            lines.append("Security references: " + ", ".join(self.references))

        if self.cve_id:
            lines.append(f"Dataset CVE case: {self.cve_id}")

        if self.fix_commit:
            lines.append(f"Ground-truth fix commit: {self.fix_commit}")

        if self.pre_fix_commits:
            lines.append("Candidate vulnerable commits: " + ", ".join(self.pre_fix_commits[:5]))

        if self.selected_pre_fix_commit:
            lines.append(f"Current target pre-fix commit: {self.selected_pre_fix_commit}")

        if self.patch_path:
            lines.append(f"Upstream patch source: {self.patch_path}")

        if self.patch_subject:
            lines.append(f"Upstream patch subject: {self.patch_subject}")

        if self.files:
            lines.append("Changed files in the upstream fix:")
            for changed in self.files[:20]:
                lines.append(f"- {changed.summary()}")
                if changed.hunk_scopes:
                    lines.append("  likely affected scopes: " + ", ".join(changed.hunk_scopes[:4]))

        if self.patch_text.strip():
            lines.append("Raw upstream patch reference:")
            lines.append("<upstream_cve_patch>")
            lines.append(self.patch_excerpt())
            lines.append("</upstream_cve_patch>")

        return "\n".join(lines)


def load_cve_context(
    patch_path=None,
    patch_text=None,
    description=None,
    references=None,
    cve_id=None,
    fix_commit=None,
    pre_fix_commits=None,
    selected_pre_fix_commit=None,
    repo=None,
    max_patch_lines=400,
):
    if patch_path and patch_text is None:
        path = Path(patch_path).expanduser().resolve()
        patch_text = path.read_text(encoding="utf-8", errors="replace")
        patch_path = str(path)

    context = CVEContext.from_patch_text(
        patch_text or "",
        patch_path=patch_path,
        description=description,
        references=references,
        cve_id=cve_id,
        fix_commit=fix_commit,
        pre_fix_commits=pre_fix_commits,
        selected_pre_fix_commit=selected_pre_fix_commit,
        max_patch_lines=max_patch_lines,
    )

    if repo:
        context.resolve_repo_matches(repo.get_tracked_files())

    return context


def load_cve_context_from_args(args, repo=None):
    if not (
        args.cve_patch
        or getattr(args, "cve_fix_commit", None)
        or args.cve_description
        or args.cve_reference
        or args.cve_dataset
        or args.cve_case
        or getattr(args, "cve_id", None)
    ):
        return None

    dataset_entry = None
    selected_pre_fix_commit = args.cve_pre_fix_commit
    patch_text = None
    patch_path = args.cve_patch
    description = args.cve_description
    references = list(args.cve_reference)
    cve_id = getattr(args, "cve_id", None)
    fix_commit = getattr(args, "cve_fix_commit", None)

    if args.cve_dataset:
        dataset = load_cve_dataset(args.cve_dataset)
        dataset_entry = select_cve_dataset_entry(dataset, args.cve_case)
        selected_pre_fix_commit = resolve_selected_pre_fix_commit(
            dataset_entry,
            repo=repo,
            requested_commit=args.cve_pre_fix_commit,
        )

        if not patch_path and repo is not None:
            try:
                patch_text = resolve_commit_patch_with_context(
                    repo,
                    dataset_entry.fix_commit,
                    function_context=True,
                )
                patch_path = f"git-show:-W:{dataset_entry.fix_commit}"
            except Exception:
                patch_text = None

        description = merge_cve_descriptions(
            description,
            build_dataset_description(dataset_entry, selected_pre_fix_commit),
        )
        references = dedupe([dataset_entry.cve] + references)
        cve_id = dataset_entry.cve
        fix_commit = dataset_entry.fix_commit

    if fix_commit and repo is not None and not patch_path and patch_text is None:
        patch_text = resolve_commit_patch_with_context(repo, fix_commit, function_context=True)
        patch_path = f"git-show:-W:{fix_commit}"

    if fix_commit and not selected_pre_fix_commit and repo is not None:
        selected_pre_fix_commit = resolve_commit_parent(repo, fix_commit)

    if fix_commit and not description:
        description = build_direct_commit_description(
            cve_id=cve_id,
            fix_commit=fix_commit,
            selected_pre_fix_commit=selected_pre_fix_commit,
        )

    return load_cve_context(
        patch_path=patch_path,
        patch_text=patch_text,
        description=description,
        references=references,
        cve_id=cve_id,
        fix_commit=fix_commit,
        pre_fix_commits=dataset_entry.pre_fix_commits if dataset_entry else None,
        selected_pre_fix_commit=selected_pre_fix_commit,
        repo=repo,
        max_patch_lines=args.cve_max_patch_lines,
    )


def load_cve_dataset(dataset_path):
    path = Path(dataset_path).expanduser().resolve()
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, list):
        raise ValueError("CVE dataset must be a JSON list")
    return [CVEDatasetEntry.from_dict(item) for item in data]


def select_cve_dataset_entry(entries, selector):
    if not entries:
        raise ValueError("CVE dataset is empty")

    if selector is None:
        if len(entries) == 1:
            return entries[0]
        raise ValueError("Please provide --cve-case when the dataset contains multiple cases")

    selector = selector.strip()
    if selector.isdigit():
        index = int(selector)
        if index < 0 or index >= len(entries):
            raise ValueError(f"CVE dataset index out of range: {selector}")
        return entries[index]

    selector_lower = selector.lower()
    for entry in entries:
        if entry.cve.lower() == selector_lower:
            return entry

    raise ValueError(f"CVE dataset case not found: {selector}")


def format_cve_dataset_entries(entries):
    lines = []
    for index, entry in enumerate(entries):
        lines.append(
            f"[{index}] {entry.cve} fix={entry.fix_commit[:12]} pre_fix={len(entry.pre_fix_commits)}"
        )
    return lines


def resolve_commit_patch(repo, commit):
    return resolve_commit_patch_with_context(repo, commit, function_context=False)


def resolve_commit_patch_with_context(repo, commit, function_context=False):
    repo_path = resolve_repo_path(repo)
    cmd = [
        "git",
        "-C",
        str(repo_path),
        "show",
        "--patch",
        "--stat=0",
        "--format=email",
    ]
    if function_context:
        cmd.append("-W")
    cmd.append(commit)
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def resolve_repo_path(repo):
    if hasattr(repo, "root"):
        return Path(repo.root).resolve()

    git_repo = getattr(repo, "repo", None)
    if git_repo is not None and getattr(git_repo, "working_tree_dir", None):
        return Path(git_repo.working_tree_dir).resolve()

    if getattr(repo, "working_tree_dir", None):
        return Path(repo.working_tree_dir).resolve()

    return Path(repo).resolve()


def resolve_commit_parent(repo, commit):
    git_repo = getattr(repo, "repo", repo)
    if hasattr(git_repo, "git"):
        return git_repo.git.rev_parse(f"{commit}^").strip()
    cmd = ["git", "-C", str(Path(repo).resolve()), "rev-parse", f"{commit}^"]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()


def resolve_selected_pre_fix_commit(entry, repo=None, requested_commit=None):
    if requested_commit:
        return requested_commit

    if repo is None:
        return None

    current_head = repo.get_head_commit_sha()
    if not current_head:
        return None

    for candidate in entry.pre_fix_commits:
        if candidate == current_head or candidate.startswith(current_head) or current_head.startswith(
            candidate
        ):
            return candidate

    return None


def build_dataset_description(entry, selected_pre_fix_commit=None):
    parts = [
        f"Dataset case {entry.cve}. Ground-truth fix commit is {entry.fix_commit}.",
        "Treat the listed pre-fix commits as vulnerable target versions.",
    ]
    if entry.pre_fix_commits:
        parts.append("Candidate pre-fix commits: " + ", ".join(entry.pre_fix_commits))
    if selected_pre_fix_commit:
        parts.append(f"Current target commit is {selected_pre_fix_commit}.")
    return " ".join(parts)


def build_direct_commit_description(cve_id=None, fix_commit=None, selected_pre_fix_commit=None):
    parts = []
    if cve_id:
        parts.append(f"Dataset case or direct input CVE is {cve_id}.")
    if fix_commit:
        parts.append(f"Ground-truth fix commit is {fix_commit}.")
    if selected_pre_fix_commit:
        parts.append(f"Target vulnerable parent commit is {selected_pre_fix_commit}.")
    if not parts:
        return None
    parts.append("Infer the minimal safe backport from the upstream fix commit.")
    return " ".join(parts)


def merge_cve_descriptions(*parts):
    merged = []
    for part in parts:
        if part:
            merged.append(part.strip())
    return " ".join(merged) if merged else None


def parse_patch_files(patch_text):
    if "*** Begin Patch" in patch_text or "*** Update File:" in patch_text:
        return parse_apply_patch_files(patch_text), "aider"
    return parse_unified_diff_files(patch_text), "unified"


def parse_unified_diff_files(patch_text):
    files = []
    current = None

    for line in patch_text.splitlines():
        match = DIFF_GIT_RE.match(line)
        if match:
            current = CVEChangedFile(
                path=normalize_diff_path(match.group(2)) or normalize_diff_path(match.group(1)) or "",
                old_path=normalize_diff_path(match.group(1)),
                new_path=normalize_diff_path(match.group(2)),
            )
            files.append(current)
            continue

        if current is None:
            continue

        if line.startswith("new file mode"):
            current.change_type = "add"
            continue

        if line.startswith("deleted file mode"):
            current.change_type = "delete"
            continue

        if line.startswith("--- "):
            current.old_path = normalize_diff_path(line[4:].strip())
            continue

        if line.startswith("+++ "):
            current.new_path = normalize_diff_path(line[4:].strip())
            current.path = current.new_path or current.old_path or current.path
            if current.old_path is None:
                current.change_type = "add"
            if current.new_path is None:
                current.change_type = "delete"
            continue

        hunk = HUNK_SCOPE_RE.match(line)
        if hunk:
            scope = (hunk.group(1) or "").strip()
            if scope:
                current.hunk_scopes.append(scope)
            continue

        if line.startswith("+") and not line.startswith("+++"):
            current.added_lines += 1
            continue

        if line.startswith("-") and not line.startswith("---"):
            current.removed_lines += 1

    for changed in files:
        changed.hunk_scopes = dedupe(changed.hunk_scopes)

    return [changed for changed in files if changed.path]


def parse_apply_patch_files(patch_text):
    files = []
    current = None

    for line in patch_text.splitlines():
        match = APPLY_PATCH_ACTION_RE.match(line)
        if match:
            current = CVEChangedFile(
                path=match.group(2).strip(),
                change_type=match.group(1).lower(),
            )
            files.append(current)
            continue

        if current is None:
            continue

        if line.startswith("@@"):
            scope = line[2:].strip()
            if scope:
                current.hunk_scopes.append(scope)
            continue

        if line.startswith("+") and not line.startswith("+++"):
            current.added_lines += 1
            continue

        if line.startswith("-") and not line.startswith("---"):
            current.removed_lines += 1

    for changed in files:
        changed.hunk_scopes = dedupe(changed.hunk_scopes)

    return files


def extract_patch_subject(patch_text):
    for line in patch_text.splitlines():
        match = SUBJECT_RE.match(line)
        if match:
            return match.group(1).strip()
    return None


def normalize_diff_path(path):
    if not path:
        return None

    path = path.strip()
    if path == "/dev/null":
        return None

    if path.startswith(("a/", "b/")):
        path = path[2:]

    return normalize_repo_path(path)


def normalize_repo_path(path):
    return str(Path(path).as_posix())


def extract_scope_identifiers(scope):
    identifiers = []
    for token in IDENT_RE.findall(scope):
        if token in {"if", "for", "while", "switch", "return", "struct", "enum", "union"}:
            continue
        identifiers.append(token)
    return dedupe(identifiers)


def load_cve_text_dataset(dataset_path, repo):
    path = Path(dataset_path).expanduser().resolve()
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_cve_text_dataset(text, repo=repo)


def parse_cve_text_dataset(text, repo):
    entries = []

    for line in text.splitlines():
        entry = parse_cve_text_line(line, repo=repo)
        if entry:
            entries.append(entry)

    return entries


def parse_cve_text_line(line, repo):
    line = line.strip()
    if not line:
        return None

    parts = [part.strip() for part in re.split(r"[\s,]+", line) if part.strip()]
    if len(parts) < 2:
        return None

    cve_id, fix_commit = parts[0], parts[1]
    if not COMMIT_ID_RE.match(fix_commit):
        return None

    try:
        parent_commit = resolve_commit_parent(repo, fix_commit)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    return CVEDatasetEntry(
        cve=cve_id,
        fix_commit=fix_commit,
        pre_fix_commits=[parent_commit],
    )


def dedupe(items):
    seen = set()
    result = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
