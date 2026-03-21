import json
from pathlib import Path
from unittest import TestCase

from aider.coders import Coder
from aider.cve import load_cve_context, load_cve_context_from_args
from aider.io import InputOutput
from aider.models import Model
from aider.repo import GitRepo
from aider.utils import GitTemporaryDirectory


PATCH_TEXT = """From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001
From: Test User <test@example.com>
Subject: [PATCH] net: fix missing length validation in foo_recvmsg

diff --git a/net/foo/bar.c b/net/foo/bar.c
index 1111111..2222222 100644
--- a/net/foo/bar.c
+++ b/net/foo/bar.c
@@ -10,6 +10,10 @@ static int foo_recvmsg(struct socket *sock, struct msghdr *msg, size_t len)
-	if (copy_to_iter(data, copy_len, &msg->msg_iter) != copy_len)
+	if (len > FOO_MSG_MAX)
+		return -EMSGSIZE;
+
+	if (copy_to_iter(data, copy_len, &msg->msg_iter) != copy_len)
 		return -EFAULT;
"""


class TestCVE(TestCase):
    def setUp(self):
        self.model = Model("gpt-3.5-turbo")

    def test_load_cve_context_parses_patch(self):
        context = load_cve_context(patch_text=PATCH_TEXT, description="Bounds check missing")

        self.assertEqual(
            context.patch_subject, "net: fix missing length validation in foo_recvmsg"
        )
        self.assertEqual(len(context.files), 1)

        changed = context.files[0]
        self.assertEqual(changed.path, "net/foo/bar.c")
        self.assertEqual(changed.added_lines, 4)
        self.assertEqual(changed.removed_lines, 1)
        self.assertIn("static int foo_recvmsg", changed.hunk_scopes[0])

    def test_cve_coder_auto_adds_exact_matches(self):
        with GitTemporaryDirectory():
            tracked = Path("net/foo")
            tracked.mkdir(parents=True)
            tracked_file = tracked / "bar.c"
            tracked_file.write_text("int foo_recvmsg(void) { return 0; }\n")

            import git

            repo = git.Repo()
            repo.git.add(str(tracked_file))
            repo.git.commit("-m", "init")

            context = load_cve_context(patch_text=PATCH_TEXT)
            io = InputOutput(pretty=False, fancy_input=False, yes=True)
            coder = Coder.create(self.model, "cve", io=io, cve_context=context)

            self.assertIn(str(tracked_file.resolve()), coder.abs_fnames)
            self.assertIsNone(coder.repo_map)
            chunks = coder.format_chat_chunks()
            self.assertTrue(chunks.extra_context)
            self.assertIn("net/foo/bar.c", chunks.extra_context[0]["content"])

    def test_dataset_case_restores_fix_commit_patch(self):
        with GitTemporaryDirectory():
            import git

            repo = git.Repo()
            vuln_file = Path("drivers/net/foo.c")
            vuln_file.parent.mkdir(parents=True)
            vuln_file.write_text("int foo(int len) {\n\treturn len;\n}\n")
            repo.git.add(str(vuln_file))
            repo.git.commit("-m", "vulnerable version")
            pre_fix_commit = repo.head.commit.hexsha

            vuln_file.write_text(
                "int foo(int len) {\n\tif (len > 4096)\n\t\treturn -EINVAL;\n\treturn len;\n}\n"
            )
            repo.git.add(str(vuln_file))
            repo.git.commit("-m", "net: fix foo length validation")
            fix_commit = repo.head.commit.hexsha

            dataset_file = Path("dataset.json")
            dataset_file.write_text(
                json.dumps(
                    [
                        {
                            "cve": "CVE-TEST-0001",
                            "fix_commit": fix_commit,
                            "pre_fix_commits": [pre_fix_commit],
                        }
                    ]
                )
            )

            io = InputOutput(pretty=False, fancy_input=False, yes=True)
            git_repo = GitRepo(io, [], None)

            class Args:
                cve_patch = None
                cve_dataset = str(dataset_file)
                cve_case = "CVE-TEST-0001"
                cve_pre_fix_commit = pre_fix_commit
                cve_description = None
                cve_reference = []
                cve_max_patch_lines = 400

            context = load_cve_context_from_args(Args, repo=git_repo)

            self.assertEqual(context.cve_id, "CVE-TEST-0001")
            self.assertEqual(context.fix_commit, fix_commit)
            self.assertEqual(context.selected_pre_fix_commit, pre_fix_commit)
            self.assertIn("fix foo length validation", context.patch_subject)
            self.assertIn("drivers/net/foo.c", context.patch_text)

    def test_direct_fix_commit_uses_parent_commit_as_target(self):
        with GitTemporaryDirectory():
            import git

            repo = git.Repo()
            vuln_file = Path("drivers/net/bar.c")
            vuln_file.parent.mkdir(parents=True)
            vuln_file.write_text("int bar(int len) {\n\treturn len;\n}\n")
            repo.git.add(str(vuln_file))
            repo.git.commit("-m", "vulnerable version")
            pre_fix_commit = repo.head.commit.hexsha

            vuln_file.write_text(
                "int bar(int len) {\n\tif (len > 1024)\n\t\treturn -EINVAL;\n\treturn len;\n}\n"
            )
            repo.git.add(str(vuln_file))
            repo.git.commit("-m", "net: fix bar validation")
            fix_commit = repo.head.commit.hexsha

            io = InputOutput(pretty=False, fancy_input=False, yes=True)
            git_repo = GitRepo(io, [], None)

            class Args:
                cve = True
                cve_id = "CVE-TEST-0002"
                cve_fix_commit = fix_commit
                cve_patch = None
                cve_dataset = None
                cve_case = None
                cve_pre_fix_commit = None
                cve_description = None
                cve_reference = []
                cve_max_patch_lines = 400

            context = load_cve_context_from_args(Args, repo=git_repo)

            self.assertEqual(context.cve_id, "CVE-TEST-0002")
            self.assertEqual(context.fix_commit, fix_commit)
            self.assertEqual(context.selected_pre_fix_commit, pre_fix_commit)
            self.assertIn("drivers/net/bar.c", context.patch_text)
