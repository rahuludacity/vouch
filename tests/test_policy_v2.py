"""Tests for gatekeeper/policy_v2.py: the §5 argument-aware policy language.

Covers: v1-upgrade equivalence (byte-for-byte v1 files behave identically),
deny-wins, every constraint op, unknown-op rejection, and the preserved
v1 deny messages.
"""
import os
import sys
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from gatekeeper import policy_v2  # noqa: E402
from gatekeeper.policy_v2 import Policy, PolicyError, Rule, upgrade_v1_policy  # noqa: E402


def v1_policy():
    with open(os.path.join(REPO, "policy.yaml"), "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def v1_inline_decide(tasks, task_id, tool):
    """The exact v1 inline check from proxy._handle_tools_call."""
    task = tasks.get(task_id) if task_id else None
    allowed = bool(task) and tool in task.get("allow", [])
    if not allowed:
        reason = (
            f"task '{task_id}' is not granted tool '{tool}'"
            if task
            else f"unknown task '{task_id}'"
        )
        return False, reason
    return True, None


class UpgradeEquivalenceTest(unittest.TestCase):
    """A v1 file through upgrade_v1_policy() decides exactly like v1."""

    def test_upgrade_shape(self):
        v2 = upgrade_v1_policy(v1_policy())
        tasks = v2["tasks"]["deploy-staging"]
        self.assertEqual(
            [r["tool"] for r in tasks["rules"]["allow"]],
            ["read_file", "run_tests", "deploy_staging"],
        )
        self.assertEqual(
            [r["rule_id"] for r in tasks["rules"]["allow"]],
            ["v1-read_file", "v1-run_tests", "v1-deploy_staging"],
        )
        self.assertEqual(tasks["rules"]["deny"], [])
        for r in tasks["rules"]["allow"]:
            self.assertNotIn("args", r)

    def test_decide_matches_v1_inline(self):
        raw = v1_policy()
        policy = Policy.from_v1_dict(raw)
        matrix = []
        for task_id in ["deploy-staging", "db-migration-review",
                        "no-such-task", None, ""]:
            for tool in ["read_file", "run_tests", "deploy_staging",
                         "delete_database", "exec", ""]:
                for args in [{}, {"path": "x"}, {"a": 1}]:
                    matrix.append((task_id, tool, args))
        for task_id, tool, args in matrix:
            want_allowed, want_reason = v1_inline_decide(
                raw["tasks"], task_id, tool)
            got_allowed, got_reason, rule_id = policy.decide(task_id, tool, args)
            self.assertEqual(got_allowed, want_allowed,
                             f"task={task_id} tool={tool}")
            self.assertEqual(got_reason, want_reason,
                             f"task={task_id} tool={tool}")
            if got_allowed:
                self.assertEqual(rule_id, f"v1-{tool}")
            else:
                self.assertIsNone(rule_id)

    def test_input_dict_not_mutated(self):
        raw = v1_policy()
        before = yaml.safe_dump(raw, sort_keys=True)
        upgrade_v1_policy(raw)
        self.assertEqual(yaml.safe_dump(raw, sort_keys=True), before)

    def test_mixed_v1_v2_file(self):
        d = {
            "tasks": {
                "old": {"allow": ["read_file"]},
                "new": {"version": 2, "rules": {
                    "allow": [{"rule_id": "r1", "tool": "read_file",
                               "args": {"path": {"prefix": "/w/"}}}],
                    "deny": []}},
            }
        }
        p = Policy.from_dict(d)
        self.assertTrue(p.decide("old", "read_file", {})[0])
        self.assertTrue(p.decide("new", "read_file", {"path": "/w/a"})[0])
        self.assertFalse(p.decide("new", "read_file", {"path": "/x"})[0])


class EvaluationTest(unittest.TestCase):
    def setUp(self):
        self.policy = Policy.from_dict({
            "version": 3,
            "tasks": {
                "deploy": {
                    "version": 3,
                    "rules": {
                        "allow": [
                            {"rule_id": "read-ws", "tool": "read_file",
                             "args": {"path": {"prefix": "/workspace/"}}},
                            {"rule_id": "deploy-staging", "tool": "deploy_staging",
                             "args": {"build": {"regex": "^[0-9a-f]{6,40}$"},
                                      "env": {"in": ["staging"]}}},
                            {"rule_id": "run-any", "tool": "run_tests"},
                            {"rule_id": "retries", "tool": "retry",
                             "args": {"n": {"range": {"min": 1, "max": 5}}}},
                            {"rule_id": "named", "tool": "greet",
                             "args": {"who": {"equals": "bob"},
                                      "title": {"required": True}}},
                        ],
                        "deny": [
                            {"rule_id": "no-prod", "tool": "deploy_staging",
                             "args": {"env": {"equals": "prod"}}},
                            {"rule_id": "no-destructive",
                             "tool": "delete_database"},
                        ],
                    },
                }
            },
        })

    def decide(self, tool, args):
        return self.policy.decide("deploy", tool, args)

    def test_deny_wins_over_allow(self):
        # matches the allow rule's tool but the deny rule fires first
        ok, reason, rule_id = self.decide(
            "deploy_staging", {"build": "abc123", "env": "prod"})
        self.assertFalse(ok)
        self.assertEqual(reason, "denied by rule 'no-prod'")
        self.assertEqual(rule_id, "no-prod")

    def test_deny_tool_only(self):
        ok, reason, rule_id = self.decide("delete_database", {"target": "prod"})
        self.assertFalse(ok)
        self.assertEqual(rule_id, "no-destructive")

    def test_allow_with_arg_constraints(self):
        ok, reason, rule_id = self.decide(
            "deploy_staging", {"build": "a1b2c3", "env": "staging"})
        self.assertTrue(ok)
        self.assertIsNone(reason)
        self.assertEqual(rule_id, "deploy-staging")

    def test_allow_constraint_and_semantics(self):
        # build matches but env doesn't -> no rule matches -> default deny
        ok, reason, rule_id = self.decide(
            "deploy_staging", {"build": "a1b2c3", "env": "dev"})
        self.assertFalse(ok)
        self.assertEqual(reason,
                         "task 'deploy' is not granted tool 'deploy_staging'")
        self.assertIsNone(rule_id)
        # missing constrained arg -> no match
        ok, _, _ = self.decide("deploy_staging", {"build": "a1b2c3"})
        self.assertFalse(ok)

    def test_prefix(self):
        self.assertTrue(self.decide("read_file", {"path": "/workspace/a"})[0])
        self.assertFalse(self.decide("read_file", {"path": "/etc/x"})[0])
        self.assertFalse(self.decide("read_file", {"path": 123})[0])

    def test_regex(self):
        ok, _, _ = self.decide("deploy_staging",
                               {"build": "ABC123", "env": "staging"})
        self.assertFalse(ok)  # uppercase not in [0-9a-f]
        ok, _, _ = self.decide("deploy_staging",
                               {"build": "a1", "env": "staging"})
        self.assertFalse(ok)  # too short

    def test_range(self):
        self.assertTrue(self.decide("retry", {"n": 3})[0])
        self.assertTrue(self.decide("retry", {"n": 1})[0])
        self.assertTrue(self.decide("retry", {"n": 5})[0])
        self.assertFalse(self.decide("retry", {"n": 0})[0])
        self.assertFalse(self.decide("retry", {"n": 6})[0])
        self.assertFalse(self.decide("retry", {"n": "3"})[0])
        self.assertFalse(self.decide("retry", {"n": True})[0])

    def test_equals_and_required(self):
        self.assertTrue(
            self.decide("greet", {"who": "bob", "title": "dr"})[0])
        self.assertFalse(
            self.decide("greet", {"who": "bob"})[0])  # title required
        self.assertFalse(
            self.decide("greet", {"who": "alice", "title": "dr"})[0])

    def test_tool_only_rule(self):
        self.assertTrue(self.decide("run_tests", {"anything": 1})[0])

    def test_unknown_task(self):
        ok, reason, rule_id = self.policy.decide("nope", "read_file", {})
        self.assertFalse(ok)
        self.assertEqual(reason, "unknown task 'nope'")
        self.assertIsNone(rule_id)

    def test_policy_version_recorded(self):
        self.assertEqual(self.policy.version, 3)


class SchemaValidationTest(unittest.TestCase):
    def test_unknown_op_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"tasks": {"t": {"rules": {
                "allow": [{"rule_id": "r", "tool": "x",
                           "args": {"a": {"contains": "y"}}}],
                "deny": []}}}})

    def test_bad_regex_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"tasks": {"t": {"rules": {
                "allow": [{"rule_id": "r", "tool": "x",
                           "args": {"a": {"regex": "([bad"}}}],
                "deny": []}}}})

    def test_multi_op_mapping_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"tasks": {"t": {"rules": {
                "allow": [{"rule_id": "r", "tool": "x",
                           "args": {"a": {"prefix": "/x",
                                          "equals": "/x"}}}],
                "deny": []}}}})

    def test_rule_needs_tool(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"tasks": {"t": {"rules": {
                "allow": [{"rule_id": "r"}], "deny": []}}}})

    def test_in_operand_must_be_list(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"tasks": {"t": {"rules": {
                "allow": [{"rule_id": "r", "tool": "x",
                           "args": {"a": {"in": "notalist"}}}],
                "deny": []}}}})

    def test_version_for(self):
        p = Policy.from_dict({"version": 1, "tasks": {
            "v2task": {"version": 2, "rules": {
                "allow": [{"rule_id": "r", "tool": "x"}], "deny": []}},
            "v1task": {"allow": ["x"]},  # v1 schema -> version 1
        }})
        self.assertEqual(p.version_for("v2task"), 2)
        self.assertEqual(p.version_for("v1task"), 1)
        self.assertEqual(p.version_for("nope"), 1)  # file default

    # -- RE2-style regex subset -------------------------------------------
    def _rule_with_regex(self, pattern):
        return Rule.from_dict({"rule_id": "r", "tool": "x",
                               "args": {"a": {"regex": pattern}}})

    def test_regex_rejects_backreference(self):
        with self.assertRaises(PolicyError):
            self._rule_with_regex(r"(a)\1")

    def test_regex_rejects_named_backreference(self):
        with self.assertRaises(PolicyError):
            self._rule_with_regex(r"(?P<w>\w+)-(?P=w)")

    def test_regex_rejects_lookaround(self):
        for pat in (r"a(?=b)", r"a(?!b)", r"(?<=a)b", r"(?<!a)b",
                    r"(?>a+)", r"(?(1)a|b)", r"a(?#comment)b"):
            with self.assertRaises(PolicyError, msg=pat):
                self._rule_with_regex(pat)

    def test_regex_allows_re2_subset(self):
        for pat in (r"^[0-9a-f]{6,40}$", r"(?:ab)+", r"(?P<word>\w+)",
                    r"(?i)abc", r"(?i:abc)", r"\d+\.\d+", r"[(\[{]",
                    r"\\", r"\(?:not-a-group\)", r"[ab]+", r"(\d+)-(\d+)"):
            rule = self._rule_with_regex(pat)  # must not raise
            self.assertEqual(rule.rule_id, "r")

    def test_regex_rejects_catastrophic_shapes(self):
        # M-3: nested quantifiers and quantified alternations are the
        # classic catastrophic-backtracking shapes — rejected at load.
        for pat in (r"(a+)+$", r"(a+)+", r"(a*)*", r"(x+)*", r"(a|aa)+$",
                    r"(?:a|b)+", r"(a|b)*", r"(\w+)+", r"(a{2,3})+"):
            with self.assertRaises(PolicyError, msg=pat):
                self._rule_with_regex(pat)

    def test_regex_catastrophic_rejected_fast(self):
        # The review's example (a+)+$ is refused at load, not evaluated.
        import time
        t0 = time.time()
        with self.assertRaises(PolicyError):
            self._rule_with_regex(r"(a+)+$")
        self.assertLess(time.time() - t0, 5.0)

    def test_regex_timeout_fails_decision_closed(self):
        # Defense in depth, proven against the real failure mode: a
        # catastrophic match that slips past the load-time scanner must
        # still be killed on time. CPython's re engine never releases
        # the GIL during a match, so a thread-pool watchdog cannot bound
        # it (measured: 59s elapsed vs the 0.25s budget); the match runs
        # in a worker *process* the OS preempts, and the runaway is
        # SIGTERMed. decide() then fails closed (deny).
        import re as _re
        import time as _t
        import gatekeeper.policy_v2 as pv
        evil = _re.compile(r"(a|a)*$")  # scanner would reject; the
        # watchdog is the backstop for shapes it misses
        t0 = _t.monotonic()
        with self.assertRaises(pv.RegexTimeout):
            pv._match_regex_guarded(evil, "a" * 28 + "b")
        dt = _t.monotonic() - t0
        self.assertLess(dt, 5.0, f"watchdog did not bound the match: {dt}s")
        self.assertGreaterEqual(dt, 0.2, f"suspiciously fast: {dt}s")
        # the pool heals itself: the next match spawns a fresh worker
        self.assertTrue(pv._match_regex_guarded(
            _re.compile(r"^b+$"), "bbb"))
        # and a timed-out allow rule denies the whole decision
        rule = self._rule_with_regex(r"a+$")
        real_search = pv._regex_pool.search
        pv._regex_pool.search = lambda *a, **k: (True, False)
        try:
            pol = pv.Policy({"t": {"version": 1, "allow": [rule], "deny": []}},
                            version=1)
            allowed, reason, _ = pol.decide("t", "x", {"a": "aaa"})
            self.assertFalse(allowed)
            self.assertIn("fail closed", reason)
        finally:
            pv._regex_pool.search = real_search

    def test_regex_escaped_backslash_digit_ok(self):
        # \\1 is an escaped backslash + "1", not a backreference
        rule = self._rule_with_regex(r"\\\\1")
        self.assertTrue(rule.matches("x", {"a": "\\\\1"}))

    def test_regex_long_value_fails_closed(self):
        rule = self._rule_with_regex(r"a+")
        self.assertFalse(rule.matches("x", {"a": "a" * 5000}))
        self.assertTrue(rule.matches("x", {"a": "a" * 4096}))


class NotificationAllowlistTest(unittest.TestCase):
    """C-1: the allow_notifications schema — explicit permit, default deny."""

    def test_default_is_deny_all(self):
        p = Policy.from_dict({"tasks": {}})
        self.assertEqual(p.allow_notifications, ())
        self.assertFalse(p.notification_allowed("notifications/initialized"))
        self.assertFalse(p.notification_allowed("tools/call"))

    def test_listed_method_permitted(self):
        p = Policy.from_dict({"tasks": {},
                              "allow_notifications": ["notifications/initialized"]})
        self.assertTrue(p.notification_allowed("notifications/initialized"))
        self.assertFalse(p.notification_allowed("ping"))

    def test_non_string_method_never_permitted(self):
        p = Policy.from_dict({"tasks": {},
                              "allow_notifications": ["notifications/initialized"]})
        self.assertFalse(p.notification_allowed(None))
        self.assertFalse(p.notification_allowed(42))
        self.assertFalse(p.notification_allowed(["notifications/initialized"]))

    def test_non_list_rejected_at_load(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"tasks": {},
                              "allow_notifications": "notifications/initialized"})

    def test_non_string_entry_rejected_at_load(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"tasks": {},
                              "allow_notifications": ["ok", 42]})

    def test_shipped_policy_permits_handshake_only(self):
        # the repo's own policy.yaml must keep working through from_dict
        p = Policy.from_dict(v1_policy())
        self.assertTrue(p.notification_allowed("notifications/initialized"))
        self.assertFalse(p.notification_allowed("notifications/cancelled"))


if __name__ == "__main__":
    unittest.main()
