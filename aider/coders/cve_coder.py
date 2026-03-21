from .cve_prompts import CVEPrompts
from .patch_coder import PatchCoder


class CVECoder(PatchCoder):
    """Backport and adapt upstream CVE/security patches to the current tree."""

    edit_format = "cve"
    gpt_prompts = CVEPrompts()

    def __init__(self, *args, cve_context=None, cve_auto_add=True, **kwargs):
        self.cve_context = cve_context
        self.cve_auto_add = cve_auto_add
        super().__init__(*args, **kwargs)
        # Linux-sized CVE workflows rely on targeted localization, not repo-map scans.
        self.repo_map = None

        if self.cve_context and self.repo:
            self.cve_context.resolve_repo_matches(self.repo.get_tracked_files())

        if self.cve_context and self.cve_auto_add:
            for rel_fname in self.cve_context.exact_matches():
                self.add_rel_fname(rel_fname)

    def get_announcements(self):
        lines = super().get_announcements()
        if not self.cve_context:
            return lines

        changed_files = len(self.cve_context.files)
        exact_matches = len(self.cve_context.exact_matches())
        summary = f"CVE context: {changed_files} upstream files, {exact_matches} exact repo matches"
        if self.cve_context.patch_subject:
            summary += f" ({self.cve_context.patch_subject})"
        lines.append(summary)
        return lines

    def get_extra_context_messages(self):
        messages = super().get_extra_context_messages()
        if not self.cve_context:
            return messages

        messages.extend(
            [
                dict(role="user", content=self.cve_context.to_prompt()),
                dict(
                    role="assistant",
                    content=(
                        "Ok, I will adapt the upstream security fix to this repository and"
                        " preserve the same security invariant."
                    ),
                ),
            ]
        )
        return messages
