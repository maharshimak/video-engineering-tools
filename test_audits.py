"""Run: python -B -m unittest -v. Git writes occur only in disposable fixtures."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent


@unittest.skipUnless(shutil.which('git'), 'Git is required')
class AuditTests(unittest.TestCase):
    def setUp(self):
        parent = HERE/'.test-work'
        parent.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-repository-', dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.repo = self.base/'repo'
        self.repo.mkdir()
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
        self.git('init', '--initial-branch=main')
        (self.repo/'fixture.py').write_text('value = 1\n')
        self.git('add', 'fixture.py')
        self.git('commit', '-m', 'Synthetic fixture')

    def git(self, *args):
        return subprocess.run(['git', '-c', 'core.hooksPath=NUL', '-c', 'core.fsmonitor=false', '-c', 'commit.gpgSign=false', '-c', 'user.name=Synthetic Test', '-c', 'user.email=fixture@example.test', '-C', str(self.repo), *args], check=True, capture_output=True, text=True, env=self.env, timeout=20).stdout

    def script(self, name, output):
        return subprocess.run([sys.executable, '-B', str(HERE/name), str(self.repo), '--output', str(output)], capture_output=True, text=True, encoding='utf-8', env=self.env, timeout=20)

    def test_benign_audit_preserves_head_and_contents(self):
        before = (self.git('rev-parse', 'HEAD'), (self.repo/'fixture.py').read_bytes())
        output = self.base/'audit'
        result = self.script('audit_repo.py', output)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((output/'audit.json').read_text())
        self.assertEqual(report['blob_count'], 1)
        self.assertEqual(report['secret_findings'], [])
        self.assertEqual(before, (self.git('rev-parse', 'HEAD'), (self.repo/'fixture.py').read_bytes()))

    def test_synthetic_token_findings_never_reveal_value(self):
        synthetic = 'sk-'+'proj-'+'A'*40
        (self.repo/'fixture.py').write_text('api_'+'key = "'+synthetic+'"\n')
        self.git('add', 'fixture.py')
        self.git('commit', '-m', 'Synthetic scanner input')
        output = self.base/'audit'
        result = self.script('audit_repo.py', output)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = (output/'audit.json').read_text()
        report = json.loads(text)
        self.assertTrue(any(f['rule']=='provider-token' for f in report['secret_findings']))
        self.assertNotIn(synthetic, text+result.stdout+result.stderr)
        self.assertFalse(any('digest' in f for f in report['secret_findings']))

    def test_inventory_excludes_git_metadata_and_preserves_contents(self):
        before = hashlib.sha256((self.repo/'fixture.py').read_bytes()).hexdigest()
        output = self.base/'inventory'
        result = self.script('inventory_full_snapshot.py', output)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((output/'inventory.json').read_text())
        self.assertEqual([f['path'] for f in report['files']], ['fixture.py'])
        self.assertEqual(before, hashlib.sha256((self.repo/'fixture.py').read_bytes()).hexdigest())

    def test_reports_refuse_existing_or_input_nested_paths(self):
        for script in ('audit_repo.py', 'inventory_full_snapshot.py'):
            with self.subTest(script=script):
                existing = self.base/script
                existing.mkdir()
                marker = existing/'keep.txt'
                marker.write_text('preserve')
                self.assertNotEqual(self.script(script, existing).returncode, 0)
                self.assertEqual(marker.read_text(), 'preserve')
                nested = self.repo/'report'
                self.assertNotEqual(self.script(script, nested).returncode, 0)
                self.assertFalse(nested.exists())


if __name__ == '__main__':
    unittest.main()
