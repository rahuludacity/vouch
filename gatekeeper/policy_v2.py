"""Policy engine v2: argument-aware, deterministic, in-process.

Language (§5):
    tasks.<task_id>.rules.allow / .rules.deny: list of rules
    rule: {rule_id, tool, args?}
    args.<name>: {<op>: <operand>}  — exactly one op per arg, ANDed together.

Constraint ops (closed set — anything else is a PolicyError at load time,
never evaluated):
    equals    arg == operand
    prefix    str(arg).startswith(operand)
    regex     re.search(pattern, str(arg))  (compiled once at load;
              RE2-style subset enforced at load — no backreferences or
              lookaround; values over 4096 chars fail closed)
    in        arg in operand (list)
    range     operand {min, max}, numeric, inclusive
    required  arg must be present (operand truthy; falsy = vacuous)

Evaluation (policy_v2.decide(task_id, tool, args) -> (bool, reason, rule_id)):
    1. unknown task            -> (False, "unknown task '<id>'", None)
    2. any matching deny rule  -> (False, "denied by rule '<rule_id>'", rule_id)
    3. any matching allow rule -> (True, None, rule_id)
    4. else                    -> (False, "task '<id>' is not granted tool '<tool>'", None)

Messages 1 and 4 are byte-identical to the v1 inline check so the v1
policy file keeps working through upgrade_v1_policy() with zero
behavior change. Pure: no I/O, no exceptions on the hot path.

Migration (§5.3): v1 schema tasks.<id>.allow: ["tool", ...] upgrades to
    tasks.<id>.rules.allow: [{rule_id: "v1-<tool>", tool: "<tool>"}...]
    tasks.<id>.rules.deny: []
Omitted `args` key ≡ {} (tool-only match, v1 semantics).
"""
import multiprocessing as _mp
import re
import threading as _threading
import time as _time

CONSTRAINT_OPS = ("equals", "prefix", "regex", "in", "range", "required")

# Regex constraints are RE2-style: the policy language promises patterns
# without backtracking hazards. The stdlib engine backtracks, and no RE2
# engine is available here, so at load we reject the constructs that
# separate RE2 from backtracking engines — backreferences and
# lookaround/conditional group extensions — PLUS the classic catastrophic
# shapes (nested quantifiers like (a+)+$ and quantified alternations like
# (a|aa)+$; see _check_catastrophic). Accepted patterns stay inside a
# subset that matches in linear time. As defense in depth, regex matching
# also fails closed on values longer than _REGEX_MAX_INPUT (tool args are
# short; this bounds worst-case match cost on the hot path), and every
# match runs in a worker *process* under a kill-on-timeout watchdog
# (RegexTimeout -> whole decision fails closed) in case a novel
# catastrophic shape slips past the compile-time checks. Processes, not
# threads: CPython's re engine never releases the GIL during a match, so
# a thread-pool watchdog cannot bound a catastrophic match — the waiting
# thread can't even wake up to notice the timeout.
_REGEX_MAX_INPUT = 4096
_REGEX_TIMEOUT_S = 0.25
_FLAG_ONLY = re.compile(r"[aiLmsuxU-]*\)")
_FLAG_SCOPED = re.compile(r"[aiLmsuxU-]+:")


def _check_re2_subset(arg_name, pattern):
    """Reject pattern constructs outside the RE2-style subset (load time).

    Allows: plain patterns, char classes, (?:...), (?P<name>...), and flag
    groups ((?i), (?i:...)). Rejects: backreferences (\\1, (?P=name)),
    lookahead/lookbehind, atomic groups, conditionals, comments.
    The scan is conservative: exotic char classes may be rejected too —
    that fails closed at load, where the operator can see it.
    """
    i, n = 0, len(pattern)
    in_class = False
    while i < n:
        c = pattern[i]
        if c == "\\":
            nxt = pattern[i + 1] if i + 1 < n else ""
            if not in_class and nxt in "123456789":
                raise PolicyError(
                    f"arg '{arg_name}': regex {pattern!r} uses a backreference "
                    f"(outside the RE2-style subset)")
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            continue
        if c == "(" and pattern[i + 1:i + 2] == "?":
            rest = pattern[i + 2:]
            allowed = (rest.startswith(":") or rest.startswith("P<")
                       or _FLAG_ONLY.match(rest) or _FLAG_SCOPED.match(rest))
            if not allowed:
                raise PolicyError(
                    f"arg '{arg_name}': regex {pattern!r} uses a group "
                    f"extension outside the RE2-style subset (only (?:...), "
                    f"(?P<name>...), and flag groups are allowed)")
        i += 1


class PolicyError(ValueError):
    """Raised at policy load/compile time for schema or constraint errors."""


class RegexTimeout(PolicyError):
    """A regex match exceeded the watchdog timeout — fail the decision."""


def _check_catastrophic(arg_name, pattern):
    r"""Reject the classic catastrophic-backtracking shapes (load time).

    Two shapes cause exponential backtracking on a backtracking engine:
      1. nested quantifiers:   (a+)+$  (a*)*  (x+)*
      2. quantified alternation: (a|aa)+$  (a|b)*c  — the group can match
         the same input in many ways, and the outer quantifier re-tries
         every combination.
    Both are rejected even though some instances are harmless (e.g.
    (a|b)+ on disjoint chars): the operator sees the PolicyError at load
    and rewrites the pattern (e.g. [ab]+). A quantified group WITHOUT an
    outer quantifier — (\d+)-(\d+) — is fine and stays allowed.
    """
    stack = []  # frames: {"alt": bool, "quant": bool}
    in_class = False
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            continue
        if c == "(":
            j = i + 1
            if pattern[j:j + 1] == "?":
                # Group extension (validated separately by
                # _check_re2_subset) — skip the intro so the "?" and ":"
                # are not misread as quantifiers/alternation markers.
                j += 1
                if pattern[j:j + 2] == "P<":
                    k = pattern.find(">", j + 2)
                    j = k + 1 if k != -1 else n
                elif pattern[j:j + 1] == ":":
                    j += 1
                else:
                    while j < n and pattern[j] not in "):":
                        j += 1
                    if pattern[j:j + 1] == ")":
                        i = j + 1  # (?i): zero-width flag setter, no group
                        continue
                    j += 1  # (?i: — consume the ":"
            stack.append({"alt": False, "quant": False})
            i = j
            continue
        if c == ")":
            frame = stack.pop() if stack else {"alt": False, "quant": False}
            # A group that is itself ambiguous/complex makes its parent
            # complex too: ((a+)(b+))+ nests quantifiers across the group
            # boundary and must be rejected when the parent is quantified.
            if (frame["quant"] or frame["alt"]) and stack:
                stack[-1]["quant"] = True
            nxt = pattern[i + 1] if i + 1 < n else ""
            if nxt and (nxt in "+*?" or nxt == "{"):
                if frame["quant"] or frame["alt"]:
                    raise PolicyError(
                        f"arg '{arg_name}': regex {pattern!r} has a quantified "
                        f"group containing a quantifier or alternation — "
                        f"catastrophic-backtracking shape (rewrite without "
                        f"nesting, e.g. [ab]+ instead of (a|b)+)")
            i += 1
            continue
        if c == "|":
            if stack:
                stack[-1]["alt"] = True
            i += 1
            continue
        if c in "+*?" or c == "{":
            if stack:
                stack[-1]["quant"] = True
            i += 1
            continue
        i += 1


# ---------------------------------------------------------------------------
# constraint compilation + matching
# ---------------------------------------------------------------------------

def _compile_constraint(arg_name, spec):
    """Validate one {op: operand} spec, return (op, compiled_operand)."""
    if not isinstance(spec, dict) or len(spec) != 1:
        raise PolicyError(
            f"arg '{arg_name}': constraint must be a single-op mapping like "
            f"{{prefix: \"/x/\"}}, got {spec!r}"
        )
    op, operand = next(iter(spec.items()))
    if op not in CONSTRAINT_OPS:
        raise PolicyError(
            f"arg '{arg_name}': unknown constraint op '{op}' "
            f"(allowed: {', '.join(CONSTRAINT_OPS)})"
        )
    if op == "prefix":
        if not isinstance(operand, str):
            raise PolicyError(f"arg '{arg_name}': prefix operand must be a string")
    elif op == "regex":
        if not isinstance(operand, str):
            raise PolicyError(f"arg '{arg_name}': regex operand must be a string")
        _check_re2_subset(arg_name, operand)
        _check_catastrophic(arg_name, operand)
        try:
            operand = re.compile(operand)
        except re.error as e:
            raise PolicyError(f"arg '{arg_name}': bad regex {operand!r}: {e}")
    elif op == "in":
        if not isinstance(operand, list):
            raise PolicyError(f"arg '{arg_name}': 'in' operand must be a list")
    elif op == "range":
        if not isinstance(operand, dict):
            raise PolicyError(f"arg '{arg_name}': range operand must be {{min, max}}")
        lo, hi = operand.get("min"), operand.get("max")
        for bound, name in ((lo, "min"), (hi, "max")):
            if not isinstance(bound, (int, float)) or isinstance(bound, bool):
                raise PolicyError(
                    f"arg '{arg_name}': range.{name} must be numeric, got {bound!r}"
                )
        operand = (lo, hi)
    elif op == "required":
        operand = bool(operand)
    # equals: any operand type is fine
    return op, operand


def _match_constraint(op, operand, args, arg_name):
    present = arg_name in args
    if op == "required":
        return present if operand else True
    if not present:
        return False
    val = args[arg_name]
    if op == "equals":
        return val == operand
    if op == "prefix":
        return isinstance(val, str) and val.startswith(operand)
    if op == "regex":
        return _match_regex_guarded(operand, val)
    if op == "in":
        try:
            return val in operand
        except TypeError:
            return False
    if op == "range":
        lo, hi = operand
        return (
            isinstance(val, (int, float))
            and not isinstance(val, bool)
            and lo <= val <= hi
        )
    return False  # unreachable: ops validated at compile time


# ---------------------------------------------------------------------------
# rules + policy
# ---------------------------------------------------------------------------

def _regex_worker_main(conn):
    """Worker process body: serve (pattern_str, value) -> match bool.

    Runs in a forked child that never touches parent locks — all it does
    is re.search over a pipe. A catastrophic match burns this process's
    CPU, but the OS preempts processes, so the parent always wakes from
    its timeout wait and can kill the runaway worker. (A thread pool
    cannot do this: CPython's re engine never releases the GIL during a
    match, so the parent thread can't even wake up to notice the timeout
    — verified empirically: 59s elapsed instead of the 0.25s budget.)

    Lifecycle: workers are reaped by _RegexProcessPool.close(), which the
    gatekeeper calls from its SIGTERM/SIGINT handler (a plain daemon
    atexit is not enough: SIGTERM skips atexit, and PDEATHSIG is
    thread-scoped — the worker is forked from a request handler thread,
    so handler-thread exit would wrongly kill pooled workers).

    The worker resets SIGTERM/SIGINT to default on entry: it is forked
    from the gatekeeper *after* the shutdown handler is installed, so
    without this it would inherit _shutdown and deadlock in close()
    trying to take the pool lock that was held at fork time — making
    proc.terminate() hang instead of killing it.
    """
    import signal as _signal
    _signal.signal(_signal.SIGTERM, _signal.SIG_DFL)
    _signal.signal(_signal.SIGINT, _signal.SIG_DFL)
    while True:
        try:
            pattern_str, value = conn.recv()
        except EOFError:
            return
        try:
            conn.send(("ok", re.search(pattern_str, value) is not None))
        except Exception as e:  # noqa: BLE001 - report, never die
            conn.send(("err", repr(e)))


class _RegexProcessPool:
    """Bounded pool of regex worker processes with kill-on-timeout.

    Checkout is O(1): an idle worker, or a fresh fork when below cap.
    If the pool is saturated the caller fails closed instead of queuing
    behind a regex flood. A worker that exceeds the timeout is SIGTERMed
    and replaced on next checkout — a runaway match can never wedge the
    gatekeeper or starve other tenants' requests.
    """

    def __init__(self, size=8):
        self._size = size
        self._ctx = _mp.get_context("fork")
        self._lock = _threading.Lock()
        self._idle = []  # [(Process, Connection)]
        self._live = 0
        self._workers = {}  # id(proc) -> (proc, conn): every live worker,
        # including ones checked out by request threads, so close() can
        # reap them all even mid-request.

    def _spawn(self):
        parent_conn, child_conn = self._ctx.Pipe(duplex=True)
        proc = self._ctx.Process(target=_regex_worker_main,
                                 args=(child_conn,), daemon=True)
        proc.start()
        child_conn.close()
        self._live += 1
        self._workers[id(proc)] = (proc, parent_conn)
        return proc, parent_conn

    def _discard(self, proc, conn):
        # Idempotent: close() and a racing request thread may both discard
        # the same worker; only the first one decrements the accounting.
        with self._lock:
            if self._workers.pop(id(proc), None) is None:
                return
            self._live -= 1
        try:
            conn.close()
        except OSError:
            pass
        try:
            if proc.is_alive():
                proc.terminate()
            proc.join(timeout=5)
        except Exception:
            pass

    def close(self):
        """Terminate every worker; the pool must not be used afterwards.

        Called from the gatekeeper's SIGTERM/SIGINT handler so a shutdown
        never leaves orphaned workers holding the listening sockets.
        (Daemon-ness alone does not do this: SIGTERM skips atexit.)
        Reaps checked-out workers too — an in-flight request fails closed.
        """
        with self._lock:
            workers = list(self._workers.values())
            self._idle = []
            self._closed = True
        for proc, conn in workers:
            self._discard(proc, conn)

    def search(self, pattern_str, value, timeout):
        """re.search in a worker; (timed_out: bool, matched: bool)."""
        with self._lock:
            if getattr(self, "_closed", False):
                return True, False  # shutting down: caller fails closed
            if self._idle:
                proc, conn = self._idle.pop()
            elif self._live < self._size:
                proc, conn = self._spawn()
            else:
                proc, conn = None, None
        if proc is None:
            return True, False  # saturated: caller fails closed
        try:
            conn.send((pattern_str, value))
        except OSError:
            self._discard(proc, conn)
            return True, False
        # The worker is a separate process: the OS preempts it, so this
        # poll() always wakes on time even mid-catastrophic-match.
        if not conn.poll(timeout):
            self._discard(proc, conn)
            return True, False
        try:
            kind, payload = conn.recv()
        except (EOFError, OSError):
            self._discard(proc, conn)
            return True, False
        with self._lock:
            self._idle.append((proc, conn))
        if kind == "ok":
            return False, bool(payload)
        return True, False  # worker-side error: fail closed


_regex_pool = _RegexProcessPool()


def _match_regex_guarded(compiled, val):
    """re.search under a preemptive watchdog; fail closed on timeout.

    The compile-time checks (_check_re2_subset + _check_catastrophic) are
    the primary guard; this is defense in depth in case a novel
    catastrophic shape slips through. A timeout raises RegexTimeout,
    which Policy.decide turns into a deny (fail closed for allow AND
    deny rules — a timed-out deny rule must not silently permit).

    The match runs in a worker *process*, not a thread: CPython's re
    engine holds the GIL for the whole match, so a thread-based timeout
    cannot fire while a catastrophic match burns (the waiting thread
    can't even wake up). The process pool bounds the blast radius to
    one worker, killed on timeout.
    """
    if not isinstance(val, str) or len(val) > _REGEX_MAX_INPUT:
        return False
    timed_out, matched = _regex_pool.search(
        compiled.pattern, val, _REGEX_TIMEOUT_S)
    if timed_out:
        raise RegexTimeout(
            f"regex {compiled.pattern!r} exceeded "
            f"{_REGEX_TIMEOUT_S}s on input (failing closed)")
    return matched

class Rule:
    def __init__(self, rule_id, tool, args_spec=None):
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError(f"rule needs a string rule_id, got {rule_id!r}")
        if not isinstance(tool, str) or not tool:
            raise PolicyError(f"rule '{rule_id}' needs a string tool, got {tool!r}")
        self.rule_id = rule_id
        self.tool = tool
        self.constraints = {
            name: _compile_constraint(name, spec)
            for name, spec in (args_spec or {}).items()
        }

    def matches(self, tool, args):
        if self.tool != tool:
            return False
        return all(
            _match_constraint(op, operand, args, name)
            for name, (op, operand) in self.constraints.items()
        )

    @classmethod
    def from_dict(cls, d):
        if not isinstance(d, dict):
            raise PolicyError(f"rule must be a mapping, got {d!r}")
        return cls(d.get("rule_id"), d.get("tool"), d.get("args"))

    def __repr__(self):
        return f"Rule({self.rule_id!r}, tool={self.tool!r})"


class Policy:
    """Compiled task-scoped policy. decide() is pure and deterministic."""

    def __init__(self, tasks, version=1):
        # tasks: {task_id: {"version": int, "allow": [Rule], "deny": [Rule]}}
        self.tasks = tasks
        self.version = version

    def decide(self, task_id, tool, args):
        """-> (allowed: bool, reason: str|None, rule_id: str|None).

        Never raises: a regex watchdog timeout fails the whole decision
        closed (deny), for both allow and deny rules.
        """
        args = args or {}
        task = self.tasks.get(task_id)
        if task is None:
            return False, f"unknown task '{task_id}'", None
        try:
            for rule in task["deny"]:
                if rule.matches(tool, args):
                    return False, f"denied by rule '{rule.rule_id}'", rule.rule_id
            for rule in task["allow"]:
                if rule.matches(tool, args):
                    return True, None, rule.rule_id
        except RegexTimeout as e:
            return False, f"policy evaluation aborted (fail closed): {e}", None
        return False, f"task '{task_id}' is not granted tool '{tool}'", None

    def version_for(self, task_id):
        """Policy version of the task that decided a call.

        Receipts must carry the deciding task's version, not the file's:
        v1 tasks record 1, v2 tasks record 2. Unknown tasks fall back to
        the file default.
        """
        task = self.tasks.get(task_id)
        return task["version"] if task else self.version

    # -- loading ----------------------------------------------------------
    @classmethod
    def from_dict(cls, d):
        """Load a policy file dict. Accepts v2, v1, or mixed task entries."""
        if not isinstance(d, dict) or not isinstance(d.get("tasks"), dict):
            raise PolicyError("policy file needs a top-level 'tasks' mapping")
        version = d.get("version", 1)
        tasks = {}
        for task_id, entry in d["tasks"].items():
            tasks[task_id] = cls._load_task(task_id, entry or {})
        return cls(tasks, version=version)

    @classmethod
    def _load_task(cls, task_id, entry):
        if "rules" in entry:  # v2 schema
            rules = entry["rules"] or {}
            return {
                "version": entry.get("version", 1),
                "allow": [Rule.from_dict(r) for r in rules.get("allow", [])],
                "deny": [Rule.from_dict(r) for r in rules.get("deny", [])],
            }
        if "allow" in entry:  # v1 schema -> upgrade this task in place
            upgraded = upgrade_v1_policy({"tasks": {task_id: entry}})["tasks"][task_id]
            return cls._load_task(task_id, upgraded)
        raise PolicyError(
            f"task '{task_id}': needs 'rules' (v2) or 'allow' (v1), got {entry!r}"
        )

    @classmethod
    def from_v1_dict(cls, v1):
        return cls.from_dict(upgrade_v1_policy(v1))


def upgrade_v1_policy(v1_dict):
    """v1 {"tasks": {id: {"allow": [...]}}} -> v2 shape, behavior-preserving.

    Every allowed tool becomes {rule_id: "v1-<tool>", tool: "<tool>"} with no
    args constraint; deny list starts empty. The input dict is not mutated.
    """
    if not isinstance(v1_dict, dict) or not isinstance(v1_dict.get("tasks"), dict):
        raise PolicyError("v1 policy needs a top-level 'tasks' mapping")
    tasks = {}
    for task_id, entry in v1_dict["tasks"].items():
        allow = entry.get("allow", []) or []
        if not isinstance(allow, list):
            raise PolicyError(f"task '{task_id}': v1 'allow' must be a list")
        tasks[task_id] = {
            "version": 1,
            "rules": {
                "allow": [
                    {"rule_id": f"v1-{tool}", "tool": tool} for tool in allow
                ],
                "deny": [],
            },
        }
    return {"version": 1, "tasks": tasks}
