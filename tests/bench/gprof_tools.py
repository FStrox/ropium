#!/usr/bin/env python3
"""Helpers for tests/bench/profile.sh (python3 standard library only).

    gprof_tools.py fix-gmon <gmon.out> <fixed.gmon.out>
    gprof_tools.py clone-map <binary> <objcopy-redefine-syms map>
    gprof_tools.py demangle <gprof output file>...
    gprof_tools.py summary <out_dir>      (re-generates the summary of a profile.sh output dir)

Two gprof attribution artifacts are corrected (GPROF_FIX=1, the default):

1. Histogram drift. glibc rounds the histogram size up to a multiple of
   8 bytes but profil() samples with exactly 4 text bytes per bin, while
   gprof maps bins linearly over [lowpc, highpc]. The resulting drift (several
   bytes near the end of a ~1 MB text) moves the samples taken at the entry of
   hot functions into whatever function precedes them in memory (e.g. phantom
   samples for Node::has_mandatory_following_node() that belong to
   Node::nb_params()). fix-gmon rewrites highpc so that both mappings agree.

2. Ignored clone symbols. gprof drops GCC clone symbols (".isra.0",
   ".part.0", ".cold", and, depending on the following string table bytes,
   even ".constprop.0"), charging their samples and calls to the preceding
   symbol (e.g. GadgetDB hash table lookups showing up as the regex function
   "_Compiler<...>::_M_assertion()" with tens of millions of calls).
   clone-map renames them to dot-free names for a copy of the binary used
   only for analysis, and demangle turns those names back into readable ones.
"""
import os
import re
import struct
import subprocess
import sys

CLONE_MARK = "__GPCLONE__"


# ---------------------------------------------------------------- fix-gmon
def _f32(x):
    return struct.unpack("<f", struct.pack("<f", x))[0]


def fix_gmon(src, dst):
    data = bytearray(open(src, "rb").read())
    if data[:4] != b"gmon":
        raise SystemExit("fix-gmon: %s is not a gmon.out file" % src)
    off = 20  # magic(4) + version(4) + spare(12)
    while off < len(data):
        tag = data[off]
        off += 1
        if tag == 0:  # GMON_TAG_TIME_HIST
            lowpc, highpc, nbins, _rate = struct.unpack_from("<QQII", data, off)
            span = highpc - lowpc
            kcountsize = 2 * nbins
            # Same computation as glibc's __monstartup() for s_scale
            if kcountsize >= span:
                scale = 65536
            else:
                scale = int(_f32(_f32(_f32(kcountsize) / _f32(span)) * 65536))
            new_highpc = lowpc + int(round(nbins * 2 * 65536.0 / scale))
            struct.pack_into("<Q", data, off + 8, new_highpc)
            off += 24 + 16 + 2 * nbins  # header + dimen(15) + abbrev(1) + bins
        elif tag == 1:  # GMON_TAG_CG_ARC
            off += 20
        elif tag == 2:  # GMON_TAG_BB_COUNT
            (count,) = struct.unpack_from("<I", data, off)
            off += 4 + 16 * count
        else:
            raise SystemExit("fix-gmon: unknown record tag %d in %s" % (tag, src))
    open(dst, "wb").write(data)


# --------------------------------------------------------------- clone-map
def clone_map(binary, map_out):
    nm = subprocess.run(["nm", "--defined-only", binary], capture_output=True,
                        text=True, check=True).stdout
    seen = set()
    with open(map_out, "w") as fh:
        for line in nm.splitlines():
            parts = line.split()
            if len(parts) != 3 or parts[1] not in "tTwW":
                continue
            name = parts[2]
            dot = name.find(".", 1)
            if dot == -1 or name in seen:
                continue
            seen.add(name)
            suffix = name[dot + 1:].replace(".", "__")
            fh.write("%s %s%s%s\n" % (name, name[:dot], CLONE_MARK, suffix))


# ---------------------------------------------------------------- demangle
_clone_re = re.compile(r"([A-Za-z0-9_$]+)" + CLONE_MARK + r"([A-Za-z0-9_]+)")


def demangle_files(paths):
    texts = [open(p, errors="replace").read() for p in paths]
    bases = sorted({m.group(1) for t in texts for m in _clone_re.finditer(t)})
    if not bases:
        return
    try:
        res = subprocess.run(["c++filt"], input="\n".join(bases) + "\n",
                             capture_output=True, text=True, check=True).stdout.splitlines()
        names = dict(zip(bases, res)) if len(res) == len(bases) else {}
    except (OSError, subprocess.CalledProcessError):
        names = {}

    def repl(m):
        base = names.get(m.group(1), m.group(1))
        return "%s [clone .%s]" % (base, m.group(2).replace("__", "."))

    for p, t in zip(paths, texts):
        open(p, "w").write(_clone_re.sub(repl, t))


# ----------------------------------------------------------------- summary
TOP = 10
# Functions tracked in every run even when outside the top-10, matched on the
# name without parameter list / clone suffix; all matching rows are summed.
WATCH = [
    "CompilerTask::add_strategy",
    "VarContext::set",
    "VarContext::get",
    "Node::nb_params",
    "StrategyGraph::_resolve_param",
    "StrategyGraph::_resolve_all_params",
    "StrategyGraph::select_gadgets",
    "_get_valid_gadget_address",
    "Node::assign_gadget",
    "BadBytes::is_valid_address",
    "strategy_exception::~strategy_exception",
]
# Groups of (mostly library) functions, only visible with LINK_MODE=static-cxx/static
GROUPS = [
    ("[group] exception throw/unwind",
     re.compile(r"^(_Unwind_|__cxa_|__gxx_personality|__gcc_personality|uw_|execute_cfa_program|"
                r"execute_stack_op|search_object|linear_search_fdes|binary_search_|classify_object_over_fdes|"
                r"init_object|get_cie_encoding|read_encoded_value|base_from_|fde_|frame_downheap|"
                r"frame_heapsort|_dl_find_object|__dl_iterate_phdr|dl_iterate_phdr|strategy_exception::)")),
    ("[group] malloc/free/new/delete",
     re.compile(r"^(malloc|free|cfree|realloc|calloc|__libc_(malloc|free|realloc|calloc)|_int_(malloc|free|realloc)|"
                r"_int_free_|malloc_consolidate|unlink_chunk|tcache_|sysmalloc|__malloc_|"
                r"operator new|operator delete)")),
    ("[group] libc mem*/str*",
     re.compile(r"^(__)?(memcmp|bcmp|memmove|memcpy|memset|memchr|strlen|strcmp|strchr|wmemset)"
                r"(_[a-z0-9_]+)?$")),
    ("[group] PLT stubs (_init)", re.compile(r"^_init$")),
]


def base_name(fn):
    fn = re.sub(r"\s*\[clone [^\]]*\]", "", fn).strip()
    if fn.endswith(")"):
        depth = 0
        for i in range(len(fn) - 1, -1, -1):
            if fn[i] == ")":
                depth += 1
            elif fn[i] == "(":
                depth -= 1
                if depth == 0:
                    fn = fn[:i]
                    break
    return fn.strip()


def display_name(fn, width=100):
    if fn == "_init":
        return "_init [= PLT stubs]"
    if len(fn) > width:
        clone = re.findall(r"\[clone [^\]]*\]", fn)
        fn = base_name(fn) + ("(...) " + " ".join(clone) if clone else "(...)")
    if len(fn) > width:
        fn = fn[:width - 3] + "..."
    return fn


_num = re.compile(r"^[0-9]+(\.[0-9]+)?$")


def parse_flat(path):
    rows, sampled = [], 0.0
    if not os.path.exists(path):
        return rows, sampled
    for line in open(path, errors="replace"):
        f = line.split()
        if len(f) < 4 or not all(_num.match(x) for x in f[:3]):
            continue
        has_calls = len(f) >= 7 and f[3].isdigit() and _num.match(f[4]) and _num.match(f[5])
        rest = line.strip()
        for _ in range(6 if has_calls else 3):
            rest = rest.split(None, 1)[1]
        rows.append({"pct": float(f[0]), "self": float(f[2]),
                     "calls": int(f[3]) if has_calls else None, "name": rest})
        sampled = max(sampled, float(f[1]))
    return rows, sampled


def parse_stdout(path):
    info = {"result": None, "chain": 0, "error": ""}
    if not os.path.exists(path):
        return info
    in_chain = False
    for line in open(path, errors="replace"):
        line = line.rstrip("\n")
        if in_chain and line.startswith("    "):
            info["chain"] += 1
            continue
        in_chain = False
        key, _, val = line.partition(" ")
        if key in ("raw_gadgets", "load_s", "compile_s", "cpu_s", "maxrss_kb"):
            info[key] = val.strip()
        elif key == "FOUND" and not val:
            info["result"] = "FOUND"
            in_chain = True
        elif key in ("NONE", "INTERRUPTED") and not val:
            info["result"] = key
        elif key == "ERROR":
            info["result"] = "ERROR"
            info["error"] = val
    return info


def outcome(info, rc):
    r = info["result"]
    if rc == 137 or (r is None and rc == 124):
        return "KILLED (no profile)"
    if r == "FOUND":
        return "FOUND (%d items)" % info["chain"]
    if r == "NONE":
        return "ABORTED at cap (SIGINT)" if rc == 124 else "NONE (search finished)"
    if r == "INTERRUPTED":
        return "INTERRUPTED during load"
    if r == "ERROR":
        return "ERROR: " + info["error"]
    return "UNKNOWN (rc=%d)" % rc


def summary(out):
    env = {}
    for l in open(os.path.join(out, "env.txt")).read().splitlines():
        k, sep, v = l.partition(":")
        if sep and k and not k.startswith(" "):
            env.setdefault(k.strip(), v.strip())

    runs = []
    for line in open(os.path.join(out, "runs.raw")):
        name, gfile, cap, query, opts, rc, t0, t1, lb, la = line.rstrip("\n").split("\t")
        info = parse_stdout(os.path.join(out, name + ".stdout"))
        rows, sampled = parse_flat(os.path.join(out, name + ".flat.txt"))
        rc = int(rc)
        runs.append(dict(name=name, gfile=gfile, cap=cap, query=query, opts=opts, rc=rc,
                         wall="%.1f" % (float(t1) - float(t0)), load_before=lb, load_after=la,
                         info=info, rows=rows, sampled="%.2f" % sampled, outcome=outcome(info, rc)))

    def g(r, k):
        return r["info"].get(k, "-")

    def rss_mb(r):
        v = r["info"].get("maxrss_kb")
        return "%d" % (int(v) // 1024) if v else "-"

    def md(s):
        return s.replace("|", "\\|")

    with open(os.path.join(out, "runs.tsv"), "w") as fh:
        fh.write("run\tgadget_file\tquery\toptions\tcap_s\toutcome\traw_gadgets\tload_s\tcompile_s"
                 "\tcpu_s\twall_s\tsampled_s\tmaxrss_mb\trc\tloadavg_before\tloadavg_after\n")
        for r in runs:
            fh.write("\t".join([r["name"], r["gfile"], r["query"], r["opts"], r["cap"], r["outcome"],
                                g(r, "raw_gadgets"), g(r, "load_s"), g(r, "compile_s"), g(r, "cpu_s"),
                                r["wall"], r["sampled"], rss_mb(r), str(r["rc"]),
                                r["load_before"], r["load_after"]]) + "\n")

    with open(os.path.join(out, "summary.tsv"), "w") as fh:
        fh.write("run\trank\tpct_self\tself_s\tcalls\tfunction\n")
        for r in runs:
            for i, row in enumerate(r["rows"][:TOP], 1):
                fh.write("%s\t%d\t%.2f\t%.2f\t%s\t%s\n" % (
                    r["name"], i, row["pct"], row["self"],
                    "" if row["calls"] is None else row["calls"], row["name"]))

    link = env.get("link_mode", "dynamic")
    unattributed = {"dynamic": "libc (malloc/free, mem*), libstdc++, libgcc unwinder, capstone",
                    "static-cxx": "libc (malloc/free, mem*), capstone"}.get(link, "nothing (fully static)")
    L = ["# ROPium gprof profile", ""]
    L.append("- Source tree: `%s` @ `%s` (%s)" % (env.get("src_tree"), env.get("src_rev", "")[:12],
                                                  env.get("src_dirty")))
    L.append("- Date: %s" % env.get("date"))
    L.append("- Host: %s, %s cores; at start: `%s`" % (env.get("kernel"), env.get("nproc"), env.get("uptime")))
    L.append("- Build: `make PROFILE=1 BINDINGS=0 bench`, link mode `%s`; %s" % (link, env.get("compiler")))
    L.append("- gprof: %s; corrections (histogram drift, clone symbols): %s"
             % (env.get("gprof"), "on" if env.get("gprof_fix") == "1" else "off"))
    L.append("- %% = share of the gprof-sampled self time inside the bench executable (load + compile). "
             "Not sampled with this link mode: %s. `cpu s` - `sampled s` = that plus the -pg overhead "
             "itself (mcount, which gprof excludes; >50%% of the CPU time on runs dominated by tiny "
             "hot functions)." % unattributed)
    L.append("- `_init [= PLT stubs]`: samples in the PLT, which has no symbols (dynamic: mcount@plt and "
             "calls into shared libs; static: IFUNC'd libc calls such as memcmp/memcpy).")
    L.append("")
    L.append("## Runs")
    L.append("")
    L.append("| run | gadgets | query | options | cap s | outcome | load s | compile s | cpu s | wall s "
             "| sampled s | maxrss MB | loadavg before/after |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in runs:
        L.append("| %s | %s (%s) | `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s / %s |" % (
            r["name"], r["gfile"], g(r, "raw_gadgets"), r["query"], r["opts"], r["cap"], md(r["outcome"]),
            g(r, "load_s"), g(r, "compile_s"), g(r, "cpu_s"), r["wall"], r["sampled"], rss_mb(r),
            r["load_before"], r["load_after"]))
    L.append("")
    L.append("## Top-%d flat profile per run" % TOP)
    for r in runs:
        L.append("")
        L.append("### %s: %s `%s` %s" % (r["name"], r["gfile"], r["query"], r["opts"]))
        L.append("")
        L.append("%s; load %s s, compile %s s, wall %s s" % (r["outcome"], g(r, "load_s"),
                                                             g(r, "compile_s"), r["wall"]))
        L.append("")
        if not r["rows"]:
            L.append("_no profile data_")
            continue
        L.append("| # | % self | self s | calls | function |")
        L.append("|---|---|---|---|---|")
        for i, row in enumerate(r["rows"][:TOP], 1):
            L.append("| %d | %.2f | %.2f | %s | `%s` |" % (
                i, row["pct"], row["self"], "" if row["calls"] is None else row["calls"],
                md(display_name(row["name"]))))
    L.append("")
    L.append("## Watch list")
    L.append("")
    L.append("% self (calls) summed over all matching rows; `-` = never sampled nor called (or not visible "
             "with this link mode).")
    L.append("")
    L.append("| function | " + " | ".join(r["name"] for r in runs) + " |")
    L.append("|---|" + "---|" * len(runs))
    matchers = [(w, (lambda w: lambda b: b == w)(w)) for w in WATCH]
    matchers += [(label, (lambda rx: lambda b: bool(rx.match(b)))(rx)) for label, rx in GROUPS]
    for label, match in matchers:
        cells = []
        for r in runs:
            rows = [row for row in r["rows"] if match(base_name(row["name"]))]
            if not rows:
                cells.append("-")
                continue
            calls = [row["calls"] for row in rows if row["calls"] is not None]
            cells.append("%.2f%%%s" % (sum(row["pct"] for row in rows),
                                       " (%d)" % sum(calls) if calls else ""))
        L.append("| `%s` | %s |" % (label, " | ".join(cells)))
    L.append("")
    open(os.path.join(out, "summary.md"), "w").write("\n".join(L))


def main(argv):
    if len(argv) == 4 and argv[1] == "fix-gmon":
        fix_gmon(argv[2], argv[3])
    elif len(argv) == 4 and argv[1] == "clone-map":
        clone_map(argv[2], argv[3])
    elif len(argv) >= 3 and argv[1] == "demangle":
        demangle_files(argv[2:])
    elif len(argv) == 3 and argv[1] == "summary":
        summary(argv[2])
    else:
        sys.stderr.write(__doc__.split("\n\n")[1] + "\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
