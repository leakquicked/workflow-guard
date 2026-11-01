import unittest
from workflow_guard import analyze_text

class WorkflowGuardTests(unittest.TestCase):
    def test_flags_missing_permissions_and_unpinned_action(self):
        text="""name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        rules={f.rule_id for f in analyze_text(text,"ci.yml")}
        self.assertIn("WG001",rules); self.assertIn("WG002",rules)
    def test_flags_privileged_trigger_and_injection(self):
        text="""name: test
on:
  pull_request_target:
jobs:
  issue:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""
        rules={f.rule_id for f in analyze_text(text)}
        self.assertIn("WG003",rules); self.assertIn("WG004",rules)
    def test_sha_pinned_action(self):
        text="""name: test
on: push
permissions:
  contents: read
jobs:
  test:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
"""
        rules={f.rule_id for f in analyze_text(text)}
        self.assertNotIn("WG001",rules); self.assertNotIn("WG002",rules)
    def test_invalid_yaml(self):
        with self.assertRaises(ValueError): analyze_text("jobs: [")
if __name__=="__main__": unittest.main()
