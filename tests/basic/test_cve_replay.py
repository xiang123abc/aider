from pathlib import Path
from unittest import TestCase

import git

from aider.cve import CVEDatasetEntry
from aider.utils import GitTemporaryDirectory
from benchmark.cve_replay import (
    ReplayCase,
    compute_patch_id,
    expand_dataset_cases,
    get_commit_patch,
    make_case_slug,
    score_file_sets,
    summarize_replay_results,
    try_apply_patch_text,
)


class TestCVEReplay(TestCase):
    def test_expand_dataset_cases(self):
        entries = [
            CVEDatasetEntry(
                cve="CVE-TEST-1",
                fix_commit="fix1",
                pre_fix_commits=["pre1", "pre2"],
            ),
            CVEDatasetEntry(
                cve="CVE-TEST-2",
                fix_commit="fix2",
                pre_fix_commits=["pre3"],
            ),
        ]

        cases = expand_dataset_cases(entries, selectors=["CVE-TEST-2"])

        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].cve, "CVE-TEST-2")
        self.assertEqual(cases[0].pre_fix_commit, "pre3")

    def test_make_case_slug(self):
        case = ReplayCase(
            dataset_index=3,
            pre_fix_index=1,
            cve="CVE-2024-50047",
            fix_commit="fix",
            pre_fix_commit="abcdef1234567890",
        )

        self.assertEqual(make_case_slug(case), "003-CVE-2024-50047-pre01-abcdef123456")

    def test_score_file_sets(self):
        metrics = score_file_sets(
            ["a.c", "b.c"],
            ["b.c", "c.c"],
        )

        self.assertEqual(metrics["intersection_count"], 1)
        self.assertEqual(metrics["missing_expected_files"], ["a.c"])
        self.assertEqual(metrics["unexpected_files"], ["c.c"])
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["recall"], 0.5)

    def test_compute_patch_id(self):
        patch_text = """diff --git a/a.c b/a.c
--- a/a.c
+++ b/a.c
@@ -1 +1 @@
-old
+new
"""
        patch_id = compute_patch_id(patch_text)
        self.assertTrue(patch_id)

    def test_summarize_replay_results(self):
        results = [
            {
                "status": "matched_fix_tree",
                "patch_metrics": {"generated_patch_nonempty": True},
                "tree_metrics": {"all_expected_files_match_fix_tree": True},
                "validation_results": [{"passed": True}],
                "file_metrics": {"precision": 1.0, "recall": 1.0},
            },
            {
                "status": "no_edits",
                "patch_metrics": {"generated_patch_nonempty": False},
                "tree_metrics": {"all_expected_files_match_fix_tree": False},
                "validation_results": [{"passed": False}],
                "file_metrics": {"precision": 0.0, "recall": 0.0},
            },
        ]

        summary = summarize_replay_results(results)
        self.assertEqual(summary["total_cases"], 2)
        self.assertEqual(summary["cases_with_edits"], 1)
        self.assertEqual(summary["cases_matching_fix_tree"], 1)
        self.assertEqual(summary["status_counts"]["no_edits"], 1)

    def test_try_apply_patch_text(self):
        with GitTemporaryDirectory():
            repo = git.Repo()

            target = Path("drivers/hid/hid-ntrig.c")
            target.parent.mkdir(parents=True)
            target.write_text(
                "static void ntrig_report_version(struct hid_device *hdev)\n"
                "{\n"
                "\tstruct usb_device *usb_dev = hid_to_usb_dev(hdev);\n"
                "\tunsigned char *data = kmalloc(8, GFP_KERNEL);\n"
                "\n"
                "\tif (!data)\n"
                "\t\tgoto err_free;\n"
                "err_free:\n"
                "\tkfree(data);\n"
                "}\n"
            )
            repo.git.add(str(target))
            repo.git.commit("-m", "vulnerable")
            pre_fix_commit = repo.head.commit.hexsha

            target.write_text(
                "static void ntrig_report_version(struct hid_device *hdev)\n"
                "{\n"
                "\tstruct usb_device *usb_dev = hid_to_usb_dev(hdev);\n"
                "\tunsigned char *data = kmalloc(8, GFP_KERNEL);\n"
                "\n"
                "\tif (!hid_is_usb(hdev))\n"
                "\t\treturn;\n"
                "\n"
                "\tif (!data)\n"
                "\t\tgoto err_free;\n"
                "err_free:\n"
                "\tkfree(data);\n"
                "}\n"
            )
            repo.git.add(str(target))
            repo.git.commit("-m", "fixed")
            fix_commit = repo.head.commit.hexsha

            repo.git.checkout(pre_fix_commit)
            patch_text = get_commit_patch(Path.cwd(), fix_commit)
            result = try_apply_patch_text(Path.cwd(), patch_text)

            self.assertTrue(result["applied"])
            diff_text = repo.git.diff("HEAD", "--", str(target))
            self.assertIn("hid_is_usb", diff_text)
