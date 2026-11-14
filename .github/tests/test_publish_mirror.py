import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PUBLISHER = Path(__file__).resolve().parents[1] / "scripts" / "publish-mirror.sh"
BRANCH = "refs/heads/automation/upstream-sync"


class PublishMirrorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote = self.root / "remote.git"
        self.work = self.root / "work"
        self.work.mkdir()
        self.git("init", "--bare", str(self.remote))
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Mirror test")
        self.git("config", "user.email", "mirror@example.invalid")
        self.git("remote", "add", "origin", str(self.remote))
        (self.work / "entries").mkdir()
        (self.work / "entries/detection.yaml").write_text("revision: 1\n")
        for name in ["library.index.yaml", "sigmahq.sync.yaml", "huntress.sync.yaml", "ai-dfir-toolkit.sync.yaml"]:
            (self.work / name).write_text("source_commit: upstream-revision\n")
        (self.work / "trusted.txt").write_text("trusted source v1\n")
        self.git("add", ".")
        self.git("commit", "-m", "Initial main")
        self.git("push", "origin", "HEAD:main")
        self.base = self.git("rev-parse", "HEAD").strip()

        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "gh-calls.txt"
        gh = self.bin / "gh"
        gh.write_text("""#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['TEST_GH_CALLS'], 'a') as log:
    log.write(' '.join(args) + '\\n')
if args[:2] == ['pr', 'list']:
    print(os.environ.get('TEST_EXISTING_PR', ''))
elif args[:2] == ['pr', 'edit'] and os.environ.get('TEST_REPOSITORY_SCOPE_ONLY') == '1':
    sys.exit('GraphQL: organization fields require read:org; token has only repo scope')
elif args[:2] in [['pr', 'create'], ['pr', 'edit']]:
    body = pathlib.Path(args[args.index('--body-file') + 1]).read_text()
    pathlib.Path(os.environ['TEST_PR_BODY']).write_text(body)
elif args[:3] == ['api', '--method', 'PATCH']:
    assert args[3] == 'repos/CraftedSignal/library/pulls/42', args
    field = args[args.index('--field') + 1]
    assert field.startswith('body=@'), field
    pathlib.Path(os.environ['TEST_PR_BODY']).write_text(pathlib.Path(field[len('body=@'):]).read_text())
else:
    sys.exit('unexpected GitHub operation')
""")
        gh.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "GH_TOKEN": "unused-local-test-token",
            "GITHUB_REPOSITORY": "CraftedSignal/library",
            "GITHUB_RUN_ID": "123",
            "GITHUB_SERVER_URL": "https://github.com",
            "TEST_GH_CALLS": str(self.calls),
            "TEST_PR_BODY": str(self.root / "pr-body.txt"),
        }

    def git(self, *args, check=True):
        result = subprocess.run(["git", *args], cwd=self.work, text=True, capture_output=True)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout if check else result

    def remote_git(self, *args):
        return self.git("--git-dir=" + str(self.remote), *args)

    def publish(self, check=True):
        result = subprocess.run(["bash", str(PUBLISHER)], cwd=self.work, env=self.env, text=True, capture_output=True)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_publication_changes_only_automation_branch_and_generated_tree(self):
        (self.work / "entries/detection.yaml").write_text("revision: 2\n")
        (self.work / ".new-refresh-token").write_text("must never be committed")
        self.publish()
        self.assertEqual(self.remote_git("rev-parse", "refs/heads/main").strip(), self.base)
        tip = self.remote_git("rev-parse", BRANCH).strip()
        self.assertEqual(self.remote_git("show", tip + ":entries/detection.yaml"), "revision: 2\n")
        self.assertEqual(self.remote_git("show", tip + ":sigmahq.sync.yaml"), "source_commit: upstream-revision\n")
        self.assertEqual(self.remote_git("diff", "--name-only", self.base, tip), "entries/detection.yaml\n")
        self.remote_git("merge-base", "--is-ancestor", self.base, tip)
        self.assertIn(self.base, (self.root / "pr-body.txt").read_text())
        self.assertNotIn(".new-refresh-token", self.remote_git("ls-tree", "-r", "--name-only", tip))

    def test_next_snapshot_preserves_branch_history_and_new_main_source(self):
        (self.work / "entries/detection.yaml").write_text("revision: 2\n")
        self.publish()
        previous = self.remote_git("rev-parse", BRANCH).strip()
        self.git("reset", "--hard", self.base)
        (self.work / "trusted.txt").write_text("trusted source v2\n")
        self.git("add", "trusted.txt")
        self.git("commit", "-m", "Reviewed source update")
        self.git("push", "origin", "HEAD:main")
        new_main = self.git("rev-parse", "HEAD").strip()
        (self.work / "entries/detection.yaml").write_text("revision: 3\n")
        self.env["TEST_EXISTING_PR"] = "42"
        self.publish()
        tip = self.remote_git("rev-parse", BRANCH).strip()
        self.remote_git("merge-base", "--is-ancestor", previous, tip)
        self.remote_git("merge-base", "--is-ancestor", new_main, tip)
        self.assertEqual(self.remote_git("show", tip + ":trusted.txt"), "trusted source v2\n")
        self.assertEqual(self.remote_git("rev-parse", "refs/heads/main").strip(), new_main)
        self.assertEqual(self.calls.read_text().count("pr create"), 1)
        self.assertIn(new_main, (self.root / "pr-body.txt").read_text())

    def test_unexpected_staged_source_change_is_rejected_before_publication(self):
        (self.work / "trusted.txt").write_text("unreviewed source change\n")
        self.git("add", "trusted.txt")
        result = self.publish(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside generated mirror paths", result.stderr)
        self.assertFalse(self.calls.exists())
        self.assertNotEqual(self.git("--git-dir=" + str(self.remote), "show-ref", "--verify", BRANCH, check=False).returncode, 0)

    def test_existing_pr_body_update_requires_only_repository_scope(self):
        (self.work / "entries/detection.yaml").write_text("revision: 2\n")
        self.env["TEST_EXISTING_PR"] = "42"
        self.env["TEST_REPOSITORY_SCOPE_ONLY"] = "1"
        self.publish()
        calls = self.calls.read_text()
        self.assertIn("api --method PATCH repos/CraftedSignal/library/pulls/42 --field body=@", calls)
        self.assertNotIn("pr edit", calls)
        self.assertIn(self.base, (self.root / "pr-body.txt").read_text())
        self.assertEqual(self.remote_git("rev-parse", "refs/heads/main").strip(), self.base)

    def test_unchanged_snapshot_does_not_create_branch_or_pr(self):
        self.publish()
        self.assertFalse(self.calls.exists())
        self.assertNotEqual(self.git("--git-dir=" + str(self.remote), "show-ref", "--verify", BRANCH, check=False).returncode, 0)

    def test_concurrent_automation_branch_change_is_not_overwritten(self):
        (self.work / "entries/detection.yaml").write_text("revision: 2\n")
        self.publish()
        previous = self.remote_git("rev-parse", BRANCH).strip()
        tree = self.remote_git("rev-parse", previous + "^{tree}").strip()
        racing = subprocess.run(
            ["git", "--git-dir=" + str(self.remote), "-c", "user.name=Other publisher", "-c", "user.email=other@example.invalid", "commit-tree", tree, "-p", previous],
            input="Concurrent update\n", text=True, capture_output=True, check=True,
        ).stdout.strip()
        hook = self.work / ".git/hooks/pre-push"
        hook.write_text("#!/bin/sh\ngit --git-dir='" + str(self.remote) + "' update-ref '" + BRANCH + "' '" + racing + "'\n")
        hook.chmod(0o755)
        (self.work / "entries/detection.yaml").write_text("revision: 3\n")
        result = self.publish(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.remote_git("rev-parse", BRANCH).strip(), racing)
        self.assertEqual(self.calls.read_text().count("pr create"), 1)


if __name__ == "__main__":
    unittest.main()
