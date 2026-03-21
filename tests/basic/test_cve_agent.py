from pathlib import Path
from unittest import TestCase

import git

from aider.cve import parse_cve_text_dataset
from aider.cve_agent import PromptFeedbackProfile
from aider.utils import GitTemporaryDirectory


class TestCVEAgent(TestCase):
    def test_parse_cve_text_dataset_resolves_parent_commit(self):
        with GitTemporaryDirectory():
            repo = git.Repo()

            test_file = Path("drivers/net/foo.c")
            test_file.parent.mkdir(parents=True)
            test_file.write_text("int foo(void) { return 0; }\n")
            repo.git.add(str(test_file))
            repo.git.commit("-m", "vulnerable")
            parent_commit = repo.head.commit.hexsha

            test_file.write_text("int foo(void) { return 1; }\n")
            repo.git.add(str(test_file))
            repo.git.commit("-m", "fix")
            fix_commit = repo.head.commit.hexsha

            entries = parse_cve_text_dataset(f"CVE-TEST-0001,{fix_commit}\n", repo=Path.cwd())

            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].cve, "CVE-TEST-0001")
            self.assertEqual(entries[0].fix_commit, fix_commit)
            self.assertEqual(entries[0].pre_fix_commits, [parent_commit])

    def test_feedback_profile_turns_failures_into_prompt_guidance(self):
        profile = PromptFeedbackProfile()
        profile.record_result(
            {
                "case": {"cve": "CVE-TEST-1"},
                "status": "no_edits",
                "file_metrics": {
                    "recall": 0.0,
                    "precision": 0.0,
                    "unexpected_files": [],
                },
                "patch_metrics": {
                    "patch_id_matches": False,
                },
                "tree_metrics": {
                    "all_expected_files_match_fix_tree": False,
                },
                "validation_results": [{"passed": False}],
            }
        )

        prompt_prefix = profile.build_system_prompt_prefix()

        self.assertIn("concrete code edits", prompt_prefix)
        self.assertIn("cleanup ordering", prompt_prefix)
        self.assertIn("upstream fix", prompt_prefix)
