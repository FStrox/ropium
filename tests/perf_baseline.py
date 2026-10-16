#!/usr/bin/env python3
"""Corpus regression fixture and timing harness for ROPium.

Subcommands
  capture  run the case matrix and write a fixture JSON (outcome + raw chain)
  verify   run the matrix against a build and compare it with a fixture
  compare  compare two capture files (determinism check)
  timing   serial timing pass over the perf subset of a fixture
  list     print the selected case ids (and the perf subset)
  deadline run the matrix with rop.timeout set and check every compile()
           returns in time, with the fixture's result or a reported time out
  worker   internal: run one case in the current process

Every case runs in a fresh subprocess with its own temporary CWD, because
ROPium.load_rp() writes ./ropium_raw_gadgets.0 into the CWD and prints junk
to stdout. The child reports through result.json in that directory.

Caps. The compile phase is capped in CPU seconds (--timeout, enforced with
RLIMIT_CPU inside the child after loading), so the NONE/TIMEOUT boundary does
not depend on how loaded the machine is. A wall-clock backstop
(--wall-timeout) kills the whole process group. SIGINT is never used: ROPium
installs a SIGINT handler during compile() and then returns None, which would
look exactly like "no chain found".

Examples
  python3 tests/perf_baseline.py capture --lib-dir bin --jobs 3
  python3 tests/perf_baseline.py verify  --lib-dir bin --jobs 3
  python3 tests/perf_baseline.py verify  --filter '^vulnserver_3\\|'
  python3 tests/perf_baseline.py compare tests/perf_baseline.json other.json
  python3 tests/perf_baseline.py timing  --label baseline --out timing.json
  python3 tests/perf_baseline.py deadline --rop-timeout 2 --slack 0.1
"""

import argparse
import datetime
import hashlib
import json
import math
import os
import platform
import re
import resource
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LIB_DIR = os.path.join(REPO, "bin")
DEFAULT_FIXTURE = os.path.join(REPO, "tests", "perf_baseline.json")
GADGET_DIR = os.path.join(REPO, "samples", "gadgets")
FORMAT_VERSION = 1

# ---------------------------------------------------------------- case matrix
DBS = [  # (name used in case ids, file in samples/gadgets)
    ("vulnserver_3", "vulnserver_3.txt"),
    ("efssetup", "efssetup.txt"),
    ("mp3_conf", "mp3_conf.txt"),
]
HEAVY_DBS = {"mp3_conf"}  # ~440 MB RSS per process

CONFIGS = [  # (name, settings applied to the ROPium object)
    ("default", {}),
    ("badbytes", {"bad_bytes": [0x00, 0x0A, 0x0D]}),
    ("keepregs", {"keep_regs": ["esi", "edi"]}),
    ("unsafe", {"safe_mem": False}),
    # Every sample address is 0x00xxxxxx, so 'badbytes' (contains 0x00) rejects every
    # gadget. This set rejects ~4-6% of addresses, so alternate-address selection and
    # bad-byte filtering are actually exercised.
    ("badbytes_nonull", {"bad_bytes": [0x0A, 0x0D, 0x20, 0x25, 0x2F, 0x5C]}),
]

QUERIES = [  # (label used in case ids, program passed to compile())
    ("ebx = 0xdeadbeef", "ebx = 0xdeadbeef"),
    ("eax = ebx", "eax = ebx"),
    ("ecx = edx", "ecx = edx"),
    ("eax = ebx + ecx", "eax = ebx + ecx"),
    ("eax = [ebx + 4]", "eax = [ebx + 4]"),
    ("[eax + 8] = ebx", "[eax + 8] = ebx"),
    # compile() splits programs on '\n' and compiles each line in turn
    ("eax = 1; ebx = 2", "eax = 1\nebx = 2"),
    ("sys_execve(0x1234, 0, 0)", "sys_execve(0x1234, 0, 0)"),
]

# Scheduling heuristic when no previous timings are known: slow first.
_DB_RANK = {"mp3_conf": 3, "efssetup": 2, "vulnserver_3": 1}
_QUERY_RANK = {"eax = ebx + ecx": 6, "eax = [ebx + 4]": 5, "[eax + 8] = ebx": 4,
               "eax = ebx": 3, "ecx = edx": 3, "sys_execve(0x1234, 0, 0)": 2}

TIMING_EXTRA_CASES = ["efssetup|badbytes|eax = ebx + ecx",
                      "efssetup|badbytes_nonull|eax = ebx + ecx"]
OUTCOMES = ("FOUND", "NONE", "TIMEOUT", "ERROR")


def build_cases():
    cases = []
    for db, fname in DBS:
        for cfg, settings in CONFIGS:
            for label, program in QUERIES:
                cases.append({
                    "id": "%s|%s|%s" % (db, cfg, label),
                    "db": db, "db_file": fname, "config": cfg,
                    "settings": settings, "query_label": label, "query": program,
                })
    return cases


def select_cases(cases, regex):
    if not regex:
        return list(cases)
    r = re.compile(regex)
    return [c for c in cases if r.search(c["id"])]


# ---------------------------------------------------------------- helpers
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def write_json_atomic(path, obj, indent=1):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".perf_baseline_", suffix=".json", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=indent)
            f.write("\n")
        os.chmod(tmp, 0o644)  # mkstemp creates 0600
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def git(*args):
    try:
        return subprocess.run(["git", "-C", REPO] + list(args), capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def mem_available_mb():
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return 1 << 30


def r4(x):
    return None if x is None else round(x, 4)


def fmt_s(x):
    if x is None:
        return "-"
    return "%.3f" % x if x < 10 else "%.1f" % x


def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


# ---------------------------------------------------------------- worker (child side)
def worker_main(args):
    spec = json.loads(args.spec)
    out_dir = os.getcwd()

    def emit(name, obj):
        tmp = os.path.join(out_dir, name + ".tmp")
        with open(tmp, "w") as f:
            json.dump(obj, f)
        os.replace(tmp, os.path.join(out_dir, name))

    try:
        res = _run_case_inprocess(spec, emit)
    except BaseException as e:  # noqa: BLE001 - everything becomes ERROR
        res = {"outcome": "ERROR", "error": "%s: %s" % (type(e).__name__, e),
               "traceback": traceback.format_exc()[-3000:]}
    emit("result.json", res)
    sys.stdout.flush()
    sys.stderr.flush()
    # Skip interpreter teardown (freeing a 50k-gadget DB takes a while).
    os._exit(0)


def _run_case_inprocess(spec, emit):
    lib_dir = os.path.realpath(spec["lib_dir"])
    sys.path.insert(0, lib_dir)
    import ropium  # noqa: E402 - path set just above

    so = os.path.realpath(ropium.__file__)
    if os.path.dirname(so) != lib_dir:
        raise RuntimeError("imported %s, expected the module from %s" % (so, lib_dir))

    rop = ropium.ROPium(ropium.ARCH.X86)
    t0 = time.perf_counter()
    rop.load_rp(spec["db_path"])
    load_s = time.perf_counter() - t0

    s = spec["settings"]
    if "bad_bytes" in s:
        rop.bad_bytes = list(s["bad_bytes"])
    if "keep_regs" in s:
        rop.keep_regs = list(s["keep_regs"])
    if "safe_mem" in s:
        rop.safe_mem = bool(s["safe_mem"])
    rop.os = ropium.OS.LINUX
    rop_timeout = spec.get("rop_timeout")
    if rop_timeout is not None:
        rop.timeout = rop_timeout
    applied = {"bad_bytes": sorted(rop.bad_bytes), "keep_regs": sorted(rop.keep_regs),
               "safe_mem": bool(rop.safe_mem)}
    expected = {"bad_bytes": sorted(s.get("bad_bytes", [])),
                "keep_regs": sorted(s.get("keep_regs", [])),
                "safe_mem": bool(s.get("safe_mem", True))}
    if applied != expected:
        raise RuntimeError("settings not applied: wanted %r, got %r" % (expected, applied))

    cpu_before = time.process_time()
    cap = spec.get("cpu_timeout")
    if cap:
        # Default SIGXCPU action terminates the process; no core file.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        hard = resource.getrlimit(resource.RLIMIT_CPU)[1]
        soft = int(math.ceil(cpu_before + cap))
        if hard != resource.RLIM_INFINITY:
            soft = min(soft, hard)
        resource.setrlimit(resource.RLIMIT_CPU, (soft, hard))
    emit("progress.json", {"phase": "compile", "load_s": load_s, "ropium_so": so,
                           "compile_start_epoch": time.time(), "cpu_at_compile_start": cpu_before})

    t1 = time.perf_counter()
    c1 = time.process_time()
    chain = rop.compile(spec["query"])
    compile_s = time.perf_counter() - t1
    compile_cpu_s = time.process_time() - c1
    if cap:
        resource.setrlimit(resource.RLIMIT_CPU, (hard, hard))

    res = {"load_s": load_s, "compile_s": compile_s, "compile_cpu_s": compile_cpu_s,
           "ropium_so": so, "applied_settings": applied}
    if rop_timeout is not None:
        res["timed_out"] = bool(rop.timed_out)
    if chain is None:
        res["outcome"] = "NONE"
    else:
        raw = chain.dump("raw")
        if not isinstance(raw, (bytes, bytearray)):
            raise RuntimeError("dump('raw') returned %r" % type(raw))
        res["outcome"] = "FOUND"
        res["chain_hex"] = bytes(raw).hex()
        res["chain_pretty"] = chain.dump("pretty", color=False).splitlines()
    return res


# ---------------------------------------------------------------- run one case (parent side)
_RUNNING = {}  # pid -> Popen, for cleanup on Ctrl+C
_RUNNING_LOCK = threading.Lock()


def kill_all_children():
    with _RUNNING_LOCK:
        pids = list(_RUNNING)
    for pid in pids:
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def _wait_child(p, deadline):
    """Reap p with os.wait4 (for rusage); kill its process group at deadline."""
    delay = 0.005
    killed = False
    while True:
        pid, status, ru = os.wait4(p.pid, os.WNOHANG)
        if pid == p.pid:
            break
        if time.perf_counter() >= deadline:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            killed = True
            pid, status, ru = os.wait4(p.pid, 0)
            break
        time.sleep(delay)
        delay = min(delay * 2, 0.1)
    p.returncode = os.waitstatus_to_exitcode(status)
    return p.returncode, ru, killed


def run_case(case, lib_dir, cpu_timeout, wall_timeout, rop_timeout=None):
    tmp = tempfile.mkdtemp(prefix="ropium_case_")
    spec = {"lib_dir": lib_dir, "db_path": os.path.join(GADGET_DIR, case["db_file"]),
            "settings": case["settings"], "query": case["query"], "cpu_timeout": cpu_timeout}
    if rop_timeout is not None:
        spec["rop_timeout"] = rop_timeout
    cmd = [sys.executable, "-I", os.path.abspath(__file__), "worker", "--spec", json.dumps(spec)]
    out = {"id": case["id"], "db": case["db"], "config": case["config"], "query": case["query"]}
    try:
        with open(os.path.join(tmp, "stdout.txt"), "wb") as fo, \
                open(os.path.join(tmp, "stderr.txt"), "wb") as fe:
            t0 = time.perf_counter()
            p = subprocess.Popen(cmd, cwd=tmp, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe,
                                 start_new_session=True)
            with _RUNNING_LOCK:
                _RUNNING[p.pid] = p
            try:
                rc, ru, killed = _wait_child(p, t0 + wall_timeout)
            finally:
                with _RUNNING_LOCK:
                    _RUNNING.pop(p.pid, None)
            wall = time.perf_counter() - t0
            end_epoch = time.time()
        result = read_json(os.path.join(tmp, "result.json"))
        progress = read_json(os.path.join(tmp, "progress.json"))
        with open(os.path.join(tmp, "stderr.txt"), "rb") as f:
            stderr_tail = f.read()[-2000:].decode("utf-8", "replace")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    cpu_s = ru.ru_utime + ru.ru_stime
    out.update({"wall_s": r4(wall), "cpu_s": r4(cpu_s), "maxrss_mb": ru.ru_maxrss // 1024,
                "returncode": rc})
    cpu_cap_hit = False
    if progress and cpu_timeout:
        cpu_cap_hit = cpu_s >= progress["cpu_at_compile_start"] + cpu_timeout - 0.5
    if killed:
        out.update({"outcome": "TIMEOUT", "timeout_kind": "wall"})
    elif result is not None:
        out["outcome"] = result["outcome"]
        for k in ("load_s", "compile_s", "compile_cpu_s"):
            out[k] = r4(result.get(k))
        for k in ("chain_hex", "chain_pretty", "timed_out", "error", "traceback"):
            if k in result:
                out[k] = result[k]
        if result["outcome"] == "ERROR":
            out["stderr_tail"] = stderr_tail
        if rc != 0:
            out["exit_note"] = "child exited with %d after reporting its result" % rc
    elif progress and (rc == -signal.SIGXCPU or (rc == -signal.SIGKILL and cpu_cap_hit)):
        out.update({"outcome": "TIMEOUT", "timeout_kind": "cpu"})
    else:
        out.update({"outcome": "ERROR", "stderr_tail": stderr_tail,
                    "error": "child died (returncode %d) during %s" %
                             (rc, "compile" if progress else "import/load")})
    if out["outcome"] == "TIMEOUT" and progress:
        # Lower bounds: the compile was still running when it was stopped.
        out["load_s"] = r4(progress["load_s"])
        out["compile_s"] = r4(end_epoch - progress["compile_start_epoch"])
        out["compile_cpu_s"] = r4(cpu_s - progress["cpu_at_compile_start"])
    return out


# ---------------------------------------------------------------- parallel scheduler
def order_cases(cases, hint=None):
    """Longest (expected) first. hint: case id -> expected seconds (inf = timeout)."""
    def key(c):
        h = hint.get(c["id"]) if hint else None
        heur = _DB_RANK[c["db"]] * 10 + _QUERY_RANK.get(c["query_label"], 1)
        return (-(h if h is not None else -1), -heur)
    return sorted(cases, key=key)


def hint_from_fixture(fx):
    hint = {}
    for cid, r in (fx or {}).get("cases", {}).items():
        if r["outcome"] == "TIMEOUT":
            hint[cid] = float("inf")
        elif r.get("wall_s") is not None:
            hint[cid] = r["wall_s"]
    return hint


def run_matrix(cases, lib_dir, jobs, cpu_timeout, wall_timeout, max_heavy=2, min_mem_mb=700,
               hint=None, rop_timeout=None):
    pending = order_cases(cases, hint)
    total = len(pending)
    results = {}
    cond = threading.Condition()
    state = {"running": 0, "heavy": 0, "stop": False, "done": 0}
    t_start = time.perf_counter()

    def pick():
        for i, c in enumerate(pending):
            if c["db"] in HEAVY_DBS:
                if state["heavy"] >= max_heavy:
                    continue
                if state["running"] > 0 and mem_available_mb() < min_mem_mb:
                    continue
            return pending.pop(i)
        return None

    def thread_main():
        while True:
            with cond:
                while True:
                    if state["stop"] or not pending:
                        return
                    c = pick()
                    if c is not None:
                        break
                    cond.wait(timeout=5)
                heavy = c["db"] in HEAVY_DBS
                state["running"] += 1
                state["heavy"] += heavy
            try:
                r = run_case(c, lib_dir, cpu_timeout, wall_timeout, rop_timeout)
            except Exception as e:  # noqa: BLE001 - harness bug; keep going
                r = {"id": c["id"], "db": c["db"], "config": c["config"], "query": c["query"],
                     "outcome": "ERROR", "error": "harness: %s: %s" % (type(e).__name__, e)}
            with cond:
                state["running"] -= 1
                state["heavy"] -= heavy
                state["done"] += 1
                results[c["id"]] = r
                el = time.perf_counter() - t_start
                log("[%2d/%d %5.0fs] %-47s %-7s compile %7ss cpu %7ss load %6ss rss %4sMB" % (
                    state["done"], total, el, c["id"], r["outcome"], fmt_s(r.get("compile_s")),
                    fmt_s(r.get("compile_cpu_s")), fmt_s(r.get("load_s")), r.get("maxrss_mb", "-")))
                cond.notify_all()

    threads = [threading.Thread(target=thread_main, daemon=True) for _ in range(max(1, jobs))]
    for t in threads:
        t.start()
    try:
        for t in threads:
            while t.is_alive():
                t.join(0.5)
    except BaseException:
        with cond:
            state["stop"] = True
        kill_all_children()
        for t in threads:  # let run_case() remove its temp dirs
            t.join(10)
        raise
    # Matrix order, independent of completion order.
    return {c["id"]: results[c["id"]] for c in cases if c["id"] in results}, \
        time.perf_counter() - t_start


# ---------------------------------------------------------------- metadata
def collect_metadata(lib_dir, args, cases):
    so = os.path.join(lib_dir, "ropium.so")
    dirty = {}
    for path in ("libropium", "bindings", "Makefile"):
        st = git("status", "--porcelain", "--", path)
        dirty[path] = None if st is None else bool(st)
    files = {}
    for db, fname in DBS:
        p = os.path.join(GADGET_DIR, fname)
        files[db] = {"path": os.path.relpath(p, REPO), "sha256": sha256_file(p)}
    try:
        load = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        load = None
    return {
        "git_commit": git("rev-parse", "HEAD"),
        "git_branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "git_dirty": dirty,
        "lib_dir": lib_dir,
        "ropium_so_sha256": sha256_file(so) if os.path.exists(so) else None,
        "gadget_files": files,
        "timeout_cpu_s": args.timeout,
        "wall_timeout_s": args.wall_timeout,
        "jobs": getattr(args, "jobs", 1),
        "max_heavy": getattr(args, "max_heavy", None),
        "filter": args.filter,
        "n_cases": len(cases),
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "loadavg_at_start": load,
        "matrix": {"dbs": [d for d, _ in DBS], "configs": dict(CONFIGS),
                   "queries": [q for _, q in QUERIES]},
        "notes": ("ARCH.X86; rop.os = OS.LINUX for every case; settings applied after load_rp(); "
                  "chain_hex = chain.dump('raw').hex(); compile capped at timeout_cpu_s CPU "
                  "seconds (RLIMIT_CPU) with a wall_timeout_s backstop; TIMEOUT compile_s/"
                  "compile_cpu_s are lower bounds."),
    }


def counts_of(results):
    c = {k: 0 for k in OUTCOMES}
    for r in results.values():
        c[r["outcome"]] = c.get(r["outcome"], 0) + 1
    return c


def resolve_lib_dir(lib_dir):
    lib_dir = os.path.realpath(lib_dir)
    if not os.path.exists(os.path.join(lib_dir, "ropium.so")):
        sys.exit("error: %s/ropium.so not found" % lib_dir)
    return lib_dir


def resolve_wall_timeout(args):
    # Generous on purpose: the CPU cap must be what stops a case, even on a busy machine.
    if args.wall_timeout is None:
        args.wall_timeout = 4 * args.timeout + 120


def print_results_table(results):
    print("%-47s %-7s %10s %10s %8s" % ("case", "outcome", "compile_s", "cpu_s", "load_s"))
    for cid, r in results.items():
        print("%-47s %-7s %10s %10s %8s" % (cid, r["outcome"], fmt_s(r.get("compile_s")),
                                           fmt_s(r.get("compile_cpu_s")), fmt_s(r.get("load_s"))))


# ---------------------------------------------------------------- capture
def cmd_capture(args):
    lib_dir = resolve_lib_dir(args.lib_dir)
    resolve_wall_timeout(args)
    cases = select_cases(build_cases(), args.filter)
    if not cases:
        sys.exit("error: --filter matched no case")
    if (os.path.abspath(args.out) == DEFAULT_FIXTURE and os.path.exists(args.out)
            and not args.force):
        sys.exit("error: %s exists; pass --force to replace the baseline fixture, or --out" %
                 args.out)
    meta = collect_metadata(lib_dir, args, cases)
    hint = hint_from_fixture(read_json(args.order_from)) if args.order_from else None
    log("capture: %d cases, lib %s, jobs %d, cap %ss cpu / %ss wall -> %s" % (
        len(cases), lib_dir, args.jobs, args.timeout, args.wall_timeout, args.out))
    results, total = run_matrix(cases, lib_dir, args.jobs, args.timeout, args.wall_timeout,
                                args.max_heavy, args.min_mem_mb, hint)
    meta["total_wall_s"] = round(total, 1)
    meta["counts"] = counts_of(results)
    write_json_atomic(args.out, {"format": FORMAT_VERSION, "metadata": meta, "cases": results})
    print_results_table(results)
    print("counts: %s  total wall %.1fs  -> %s" % (meta["counts"], total, args.out))
    if meta["counts"]["ERROR"]:
        print("WARNING: %d case(s) ended in ERROR" % meta["counts"]["ERROR"])
        return 1
    return 0


# ---------------------------------------------------------------- verify
def cmd_verify(args):
    lib_dir = resolve_lib_dir(args.lib_dir)
    fx = read_json(args.fixture)
    if not fx:
        sys.exit("error: cannot read fixture %s" % args.fixture)
    fmeta = fx["metadata"]
    if args.timeout is None:
        args.timeout = fmeta["timeout_cpu_s"]
    resolve_wall_timeout(args)
    selected = select_cases(build_cases(), args.filter)
    cases = [c for c in selected if c["id"] in fx["cases"]]
    missing = len(selected) - len(cases)
    if args.skip_timeouts:
        cases = [c for c in cases if fx["cases"][c["id"]]["outcome"] != "TIMEOUT"]
    if not cases:
        sys.exit("error: no fixture case matches --filter")
    if missing:
        log("note: %d selected case(s) are not in the fixture and are skipped" % missing)

    failures = []
    for db, info in fmeta.get("gadget_files", {}).items():
        p = os.path.join(REPO, info["path"])
        if os.path.exists(p) and sha256_file(p) != info["sha256"]:
            failures.append("gadget file %s changed since the fixture was captured" % info["path"])

    log("verify: %d cases, lib %s vs fixture %s (commit %s), jobs %d, cap %ss cpu" % (
        len(cases), lib_dir, args.fixture, (fmeta.get("git_commit") or "?")[:10], args.jobs,
        args.timeout))
    results, total = run_matrix(cases, lib_dir, args.jobs, args.timeout, args.wall_timeout,
                                args.max_heavy, args.min_mem_mb, hint_from_fixture(fx))
    nondet = {d["id"] for d in fmeta.get("nondeterministic_cases", [])}

    rows, info_lines = [], []
    n_pass = n_info = 0
    for c in cases:
        b, n = fx["cases"][c["id"]], results[c["id"]]
        bo, no = b["outcome"], n["outcome"]
        if no == "ERROR":
            status = "FAIL"
            detail = "new ERROR: %s" % (n.get("error") or "")
        elif bo in ("FOUND", "NONE"):
            if no != bo:
                status, detail = "FAIL", "outcome %s -> %s" % (bo, no)
            elif bo == "FOUND" and n.get("chain_hex") != b.get("chain_hex"):
                status, detail = "FAIL", "chain differs: %s -> %s" % (b.get("chain_hex"),
                                                                     n.get("chain_hex"))
            elif n.get("returncode", 0) != 0 and b.get("returncode", 0) == 0:
                status, detail = "FAIL", n.get("exit_note", "bad exit status")
            else:
                status, detail = "PASS", ""
        else:  # baseline TIMEOUT / ERROR: informational
            status, detail = "INFO", "baseline %s, now %s" % (bo, no)
            if no == "FOUND":
                detail += " chain=%s" % n.get("chain_hex")
        if status == "FAIL" and c["id"] in nondet:
            detail += " (listed as nondeterministic in fixture)"
        if status == "FAIL":
            failures.append("%s: %s" % (c["id"], detail))
            if n.get("chain_pretty") or b.get("chain_pretty"):
                failures.append("  baseline: %s" % " | ".join(b.get("chain_pretty", [])))
                failures.append("  new:      %s" % " | ".join(n.get("chain_pretty", [])))
        elif status == "INFO":
            n_info += 1
            info_lines.append("%s: %s" % (c["id"], detail))
        else:
            n_pass += 1
        rows.append((c["id"], bo, no, b.get("compile_s"), n.get("compile_s"), status))

    print("%-47s %-7s %-7s %10s %10s %8s  %s" % ("case", "base", "new", "base_s", "new_s",
                                                  "speedup", "status"))
    for cid, bo, no, bs, ns, st in rows:
        sp = ""
        if bs and ns and bs > 0.01 and ns > 0:
            sp = ("%.2fx" % (bs / ns)) + ("+" if bo == "TIMEOUT" else "")
        print("%-47s %-7s %-7s %10s %10s %8s  %s" % (cid, bo, no, fmt_s(bs), fmt_s(ns), sp, st))
    if info_lines:
        print("\ninformational (baseline TIMEOUT/ERROR):")
        for l in info_lines:
            print("  " + l)
    n_fail = len(rows) - n_pass - n_info
    print("\nverify: %d cases, %d PASS, %d FAIL, %d INFO, wall %.1fs" % (
        len(rows), n_pass, n_fail, n_info, total))
    if failures:
        print("FAILURES:")
        for f in failures:
            print("  " + f)
    if args.out:
        meta = collect_metadata(lib_dir, args, cases)
        meta.update({"total_wall_s": round(total, 1), "counts": counts_of(results),
                     "verified_against": os.path.abspath(args.fixture)})
        write_json_atomic(args.out, {"format": FORMAT_VERSION, "metadata": meta, "cases": results})
        print("results written to %s" % args.out)
    print("RESULT: %s" % ("FAIL" if failures else "OK"))
    return 1 if failures else 0


# ---------------------------------------------------------------- compare
def classify_diff(a, b):
    if a is None or b is None:
        return "missing"
    ao, bo = a["outcome"], b["outcome"]
    if "TIMEOUT" in (ao, bo) and "ERROR" not in (ao, bo):
        return "timeout-boundary"
    if ao == bo == "FOUND":
        return "chain"
    return "outcome"


def cmd_compare(args):
    A, B = read_json(args.a), read_json(args.b)
    if not A or not B:
        sys.exit("error: cannot read inputs")
    ids = list(A["cases"]) + [i for i in B["cases"] if i not in A["cases"]]
    diffs = []
    for cid in ids:
        a, b = A["cases"].get(cid), B["cases"].get(cid)
        if a and b and a["outcome"] == b["outcome"] and a.get("chain_hex") == b.get("chain_hex"):
            continue
        diffs.append({"id": cid, "kind": classify_diff(a, b),
                      "a": a and a["outcome"], "b": b and b["outcome"],
                      "a_compile_cpu_s": a and a.get("compile_cpu_s"),
                      "b_compile_cpu_s": b and b.get("compile_cpu_s")})
    print("A: %s (commit %s, %s)" % (args.a, (A["metadata"].get("git_commit") or "?")[:10],
                                    A["metadata"].get("date")))
    print("B: %s (commit %s, %s)" % (args.b, (B["metadata"].get("git_commit") or "?")[:10],
                                    B["metadata"].get("date")))
    print("cases: %d in A, %d in B, %d differ" % (len(A["cases"]), len(B["cases"]), len(diffs)))
    for d in diffs:
        print("  %-47s %-16s A=%s B=%s (cpu A=%s B=%s)" % (
            d["id"], d["kind"], d["a"], d["b"], fmt_s(d["a_compile_cpu_s"]),
            fmt_s(d["b_compile_cpu_s"])))
    if args.record_into:
        target = read_json(args.record_into)
        if not target:
            sys.exit("error: cannot read %s" % args.record_into)
        other = args.b if os.path.abspath(args.record_into) == os.path.abspath(args.a) else args.a
        om = read_json(other)["metadata"]
        target["metadata"]["nondeterministic_cases"] = diffs
        target["metadata"]["determinism_check"] = {
            "compared_with": os.path.abspath(other), "other_date": om.get("date"),
            "other_git_commit": om.get("git_commit"), "other_total_wall_s": om.get("total_wall_s"),
            "identical": not diffs, "n_cases_compared": len(ids),
            "date": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}
        write_json_atomic(args.record_into, target)
        print("recorded determinism result in %s" % args.record_into)
    print("RESULT: %s" % ("IDENTICAL" if not diffs else "DIFFERENT"))
    return 1 if diffs else 0


# ---------------------------------------------------------------- timing
def perf_subset(fx, all_cases):
    fc = fx["cases"]
    ids = []
    for c in all_cases:
        r = fc.get(c["id"])
        if c["config"] == "default" and r and r["outcome"] in ("NONE", "TIMEOUT"):
            ids.append(c["id"])
    ids += [i for i in TIMING_EXTRA_CASES if i in fc]
    for db, _ in DBS:  # slowest FOUND default-config case per DB (falls back to any config)
        for cfg_filter in (("default",), None):
            found = [c["id"] for c in all_cases if c["db"] == db and fc.get(c["id"], {}).get(
                "outcome") == "FOUND" and (cfg_filter is None or c["config"] in cfg_filter)]
            if found:
                ids.append(max(found, key=lambda i: (fc[i].get("compile_cpu_s") or 0)))
                break
    seen, out = set(), []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    by_id = {c["id"]: c for c in all_cases}
    return [by_id[i] for i in out]


def _median(vals):
    vals = [v for v in vals if v is not None]
    return r4(statistics.median(vals)) if vals else None


def cmd_timing(args):
    lib_dir = resolve_lib_dir(args.lib_dir)
    resolve_wall_timeout(args)
    fx = read_json(args.fixture)
    if not fx:
        sys.exit("error: cannot read fixture %s" % args.fixture)
    cases = perf_subset(fx, build_cases())
    if args.filter:
        r = re.compile(args.filter)
        cases = [c for c in cases if r.search(c["id"])]
    if not cases:
        sys.exit("error: empty perf subset")
    log("timing '%s': %d cases serially, lib %s, cap %ss cpu" % (args.label, len(cases), lib_dir,
                                                                 args.timeout))
    t_start = time.perf_counter()
    out_cases = {}
    try:
        for c in cases:
            runs = [run_case(c, lib_dir, args.timeout, args.wall_timeout)]
            r0 = runs[0]
            if r0["outcome"] in ("FOUND", "NONE") and (r0.get("compile_s") or 0) < args.fast_threshold:
                for _ in range(args.repeat - 1):
                    runs.append(run_case(c, lib_dir, args.timeout, args.wall_timeout))
            outcomes = sorted({r["outcome"] for r in runs})
            entry = {
                "outcome": runs[0]["outcome"] if len(outcomes) == 1 else "/".join(outcomes),
                "n_runs": len(runs),
                "compile_s": _median([r.get("compile_s") for r in runs]),
                "compile_cpu_s": _median([r.get("compile_cpu_s") for r in runs]),
                "load_s": _median([r.get("load_s") for r in runs]),
                "wall_s": _median([r.get("wall_s") for r in runs]),
                "runs_compile_s": [r.get("compile_s") for r in runs],
                "maxrss_mb": max(r.get("maxrss_mb") or 0 for r in runs),
                "fixture_outcome": fx["cases"][c["id"]]["outcome"],
            }
            out_cases[c["id"]] = entry
            log("  %-47s %-7s compile %8ss (cpu %8ss, %d run%s) load %6ss" % (
                c["id"], entry["outcome"], fmt_s(entry["compile_s"]), fmt_s(entry["compile_cpu_s"]),
                entry["n_runs"], "" if entry["n_runs"] == 1 else "s", fmt_s(entry["load_s"])))
    except BaseException:
        kill_all_children()
        raise

    meta = collect_metadata(lib_dir, args, cases)
    meta.update({"label": args.label, "repeat": args.repeat, "fast_threshold_s": args.fast_threshold,
                 "total_wall_s": round(time.perf_counter() - t_start, 1),
                 "fixture": os.path.abspath(args.fixture)})
    target = args.out or args.fixture
    data = read_json(target) if os.path.exists(target) else None
    if data is None:
        if os.path.exists(target):
            sys.exit("error: %s exists but is not valid JSON" % target)
        data = {}
    data.setdefault("timing", {})[args.label] = {"metadata": meta, "cases": out_cases}
    write_json_atomic(target, data)

    ref = data["timing"].get(args.compare_label) if args.compare_label != args.label else None
    print("%-47s %-7s %10s %10s %8s" % ("case", "outcome", "compile_s", "cpu_s",
                                        "vs " + args.compare_label if ref else ""))
    for cid, e in out_cases.items():
        sp = ""
        if ref and cid in ref["cases"]:
            b = ref["cases"][cid].get("compile_s")
            if b and e["compile_s"] and b > 0.01:
                sp = "%.2fx" % (b / e["compile_s"])
        mism = "" if e["outcome"] == e["fixture_outcome"] else "  (fixture: %s)" % e["fixture_outcome"]
        print("%-47s %-7s %10s %10s %8s%s" % (cid, e["outcome"], fmt_s(e["compile_s"]),
                                             fmt_s(e["compile_cpu_s"]), sp, mism))
    print("timing '%s' written to %s (total %.1fs)" % (args.label, target, meta["total_wall_s"]))
    return 0


# ---------------------------------------------------------------- deadline
def cmd_deadline(args):
    """Check rop.timeout: every compile() returns within rop_timeout + slack seconds.

    A search that did not time out must give the fixture's result (the deadline
    never changes the search order); a search that timed out must return None.
    """
    lib_dir = resolve_lib_dir(args.lib_dir)
    if args.rop_timeout <= 0:
        sys.exit("error: --rop-timeout must be > 0")
    if args.timeout is None:
        args.timeout = 4 * args.rop_timeout + 10  # CPU backstop if the deadline is broken
    resolve_wall_timeout(args)
    fx = read_json(args.fixture)
    base_cases = fx["cases"] if fx else {}
    cases = select_cases(build_cases(), args.filter)
    if not cases:
        sys.exit("error: no case matches --filter")
    limit = args.rop_timeout + args.slack

    log("deadline: %d cases, lib %s, rop.timeout %ss, limit %ss, jobs %d, cpu backstop %ss" % (
        len(cases), lib_dir, args.rop_timeout, fmt_s(limit), args.jobs, args.timeout))
    results, total = run_matrix(cases, lib_dir, args.jobs, args.timeout, args.wall_timeout,
                                args.max_heavy, args.min_mem_mb, rop_timeout=args.rop_timeout)

    rows, failures = [], []
    for c in cases:
        n = results[c["id"]]
        b = base_cases.get(c["id"])
        bo, no = (b["outcome"] if b else "-"), n["outcome"]
        timed_out = n.get("timed_out")
        problems = []
        if no in ("ERROR", "TIMEOUT"):
            problems.append("%s: %s" % (no, n.get("error") or "compile() did not return"))
        else:
            if n["compile_s"] > limit:
                problems.append("late: compile took %ss" % fmt_s(n["compile_s"]))
            if timed_out and no != "NONE":
                problems.append("timed out but returned a chain")
            if not timed_out and bo in ("FOUND", "NONE"):
                if no != bo:
                    problems.append("finished in time but outcome %s -> %s" % (bo, no))
                elif no == "FOUND" and n.get("chain_hex") != b.get("chain_hex"):
                    problems.append("finished in time but the chain differs")
        if problems:
            failures.append("%s: %s" % (c["id"], "; ".join(problems)))
        rows.append((c["id"], bo, no, timed_out, n.get("compile_s"), "FAIL" if problems else "PASS"))

    print("%-47s %-7s %-7s %-9s %9s %12s  %s" % ("case", "base", "new", "timed_out", "compile_s",
                                                  "overshoot_ms", "status"))
    overshoots = []
    for cid, bo, no, to, cs, st in rows:
        over = ""
        if to and cs is not None:
            overshoots.append(cs - args.rop_timeout)
            over = "%.1f" % ((cs - args.rop_timeout) * 1000)
        print("%-47s %-7s %-7s %-9s %9s %12s  %s" % (cid, bo, no, "-" if to is None else to,
                                                      fmt_s(cs), over, st))
    compile_times = [r[4] for r in rows if r[4] is not None]
    print("\ndeadline: %d cases, %d timed out, %d FAIL, max compile %ss, max overshoot %s ms, "
          "wall %.1fs" % (len(rows), len(overshoots), len(failures),
                          fmt_s(max(compile_times)) if compile_times else "-",
                          "%.1f" % (max(overshoots) * 1000) if overshoots else "-", total))
    if failures:
        print("FAILURES:")
        for f in failures:
            print("  " + f)
    if args.out:
        meta = collect_metadata(lib_dir, args, cases)
        meta.update({"total_wall_s": round(total, 1), "counts": counts_of(results),
                     "rop_timeout_s": args.rop_timeout, "slack_s": args.slack})
        write_json_atomic(args.out, {"format": FORMAT_VERSION, "metadata": meta, "cases": results})
        print("results written to %s" % args.out)
    print("RESULT: %s" % ("FAIL" if failures else "OK"))
    return 1 if failures else 0


# ---------------------------------------------------------------- list
def cmd_list(args):
    fx = read_json(args.fixture)
    cases = select_cases(build_cases(), args.filter)
    if args.perf_subset:
        if not fx:
            sys.exit("error: cannot read fixture %s" % args.fixture)
        sub = {c["id"] for c in perf_subset(fx, build_cases())}
        cases = [c for c in cases if c["id"] in sub]
    for c in cases:
        r = fx["cases"].get(c["id"]) if fx else None
        print("%-47s %s" % (c["id"], "%s %ss" % (r["outcome"], fmt_s(r.get("compile_s"))) if r else ""))
    print("%d case(s)" % len(cases))
    return 0


# ---------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__.split("\n\n", 1)[1])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, jobs=True, timeout_default=400.0, timeout_default_note="fixture's value"):
        p.add_argument("--lib-dir", default=DEFAULT_LIB_DIR,
                       help="directory holding ropium.so (default: %(default)s)")
        p.add_argument("--filter", metavar="REGEX", help="only cases whose id matches (re.search)")
        p.add_argument("--timeout", type=float, default=timeout_default,
                       help="per-case compile cap in CPU seconds (default: %s)" %
                            (timeout_default_note if timeout_default is None else "%(default)s"))
        p.add_argument("--wall-timeout", type=float, default=None,
                       help="per-case wall-clock backstop incl. load (default: 4*timeout+120)")
        if jobs:
            p.add_argument("--jobs", type=int, default=3, help="parallel cases (default: %(default)s)")
            p.add_argument("--max-heavy", type=int, default=2,
                           help="max concurrent mp3_conf cases, ~440 MB each (default: %(default)s)")
            p.add_argument("--min-mem-mb", type=int, default=700,
                           help="start a heavy case only if MemAvailable >= this or nothing "
                                "else runs (default: %(default)s)")

    p = sub.add_parser("capture", help="run the matrix and write a fixture")
    common(p)
    p.add_argument("--out", default=DEFAULT_FIXTURE, help="fixture path (default: %(default)s)")
    p.add_argument("--order-from", metavar="FIXTURE",
                   help="schedule by the wall times recorded in this fixture (slowest first)")
    p.add_argument("--force", action="store_true", help="allow overwriting %s" % DEFAULT_FIXTURE)
    p.set_defaults(func=cmd_capture)

    p = sub.add_parser("verify", help="run the matrix and compare with a fixture")
    common(p, timeout_default=None)
    p.add_argument("--fixture", default=DEFAULT_FIXTURE, help="(default: %(default)s)")
    p.add_argument("--out", help="also save this run in capture format")
    p.add_argument("--skip-timeouts", action="store_true",
                   help="skip cases whose baseline outcome is TIMEOUT (informational only)")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("compare", help="compare two capture files (outcome + chain)")
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("--record-into", metavar="FIXTURE",
                   help="store the result as metadata.nondeterministic_cases in FIXTURE")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("timing", help="serial timing pass over the perf subset")
    common(p, jobs=False)
    p.add_argument("--fixture", default=DEFAULT_FIXTURE,
                   help="fixture defining the perf subset (default: %(default)s)")
    p.add_argument("--label", required=True, help="e.g. baseline, after-task-2.1")
    p.add_argument("--out", help="write timing[label] here instead of into --fixture")
    p.add_argument("--repeat", type=int, default=3, help="runs for fast cases (default: %(default)s)")
    p.add_argument("--fast-threshold", type=float, default=5.0,
                   help="cases whose first compile is below this many seconds are repeated "
                        "and the median kept (default: %(default)s)")
    p.add_argument("--compare-label", default="baseline",
                   help="print speedups against this label if present (default: %(default)s)")
    p.set_defaults(func=cmd_timing)

    p = sub.add_parser("deadline", help="check that rop.timeout bounds every compile()")
    common(p, timeout_default=None, timeout_default_note="4*rop-timeout+10")
    p.add_argument("--rop-timeout", type=float, default=2.0,
                   help="rop.timeout in seconds (default: %(default)s)")
    p.add_argument("--slack", type=float, default=0.1,
                   help="allowed overshoot in seconds (default: %(default)s)")
    p.add_argument("--fixture", default=DEFAULT_FIXTURE,
                   help="results to compare with when a search finishes in time "
                        "(default: %(default)s)")
    p.add_argument("--out", help="also save this run in capture format")
    p.set_defaults(func=cmd_deadline)

    p = sub.add_parser("list", help="print case ids")
    p.add_argument("--filter", metavar="REGEX")
    p.add_argument("--fixture", default=DEFAULT_FIXTURE)
    p.add_argument("--perf-subset", action="store_true", help="only the timing subset")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("worker", help="(internal) run one case in this process")
    p.add_argument("--spec", required=True)
    p.set_defaults(func=worker_main)

    args = ap.parse_args(argv)
    if hasattr(args, "jobs") and args.jobs < 1:
        ap.error("--jobs must be >= 1")
    if args.cmd != "worker":
        # SIGTERM -> same cleanup as Ctrl+C (kill running cases, remove temp dirs).
        def _on_term(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, _on_term)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        kill_all_children()
        log("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
