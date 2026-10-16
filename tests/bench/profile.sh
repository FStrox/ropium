#!/usr/bin/env bash
# ROPium gprof profiling harness
# ==============================
#
# Usage: tests/bench/profile.sh <src_tree> <out_dir>
#
#   <src_tree>  ROPium checkout to profile (needs tests/bench/ and the
#               'bench' / PROFILE=1 support in its Makefile)
#   <out_dir>   where the summary and the raw gprof outputs are written
#
# What it does:
#   1. Copies Makefile, libropium/ and tests/bench/ of <src_tree> (without any
#      *.o / *.gch) into a fresh temp dir and builds
#      'make PROFILE=1 BINDINGS=0 bench' there, so profiling never touches the
#      objects or bin/ of <src_tree>.
#   2. Runs the fixed profile set below, serially, each in its own temp CWD
#      under 'timeout -s INT <cap>'. ROPium aborts the search on SIGINT and
#      bench returns from main(), so gmon.out is still written.
#   3. Runs 'gprof -b -p' (flat profile) and 'gprof -b -q' (call graph) on
#      each gmon.out (with the corrections described in gprof_tools.py).
#   4. Writes into <out_dir>:
#        summary.md     run table, top-10 flat-profile rows per run, watch list
#        summary.tsv    the top-10 rows, tab separated
#        runs.tsv       one line per run (outcome, timings, rc, load average)
#        runs.raw       run metadata ('gprof_tools.py summary <out_dir>' input)
#        env.txt        source revision, compiler, host, build settings
#        build.log, gprof.log
#        <run>.stdout / <run>.stderr       bench output
#        <run>.flat.txt / <run>.graph.txt  gprof outputs
#        raw/bench, raw/<run>.gmon.out     binary + gmon.out as written by glibc
#
# Environment knobs:
#   JOBS=2            make -j value
#   RUNS="a b"        only run these profile names (default: all of them)
#   LINK_MODE=dynamic dynamic:    as the library is normally linked; time spent
#                                 in shared libs is not sampled by gprof
#                     static-cxx: -static-libstdc++ -static-libgcc, so the
#                                 C++ runtime and the unwinder (exception
#                                 throwing) are sampled too
#                     static:     -static, also samples libc (malloc/free,
#                                 mem*), i.e. ~all CPU time is attributed
#   GPROF_FIX=1       0: plain gprof output without the corrections
#   KILL_GRACE=30     seconds between the SIGINT and a SIGKILL (no profile then)
#   GADGETS_DIR       rp++ gadget files (default: <src_tree>/samples/gadgets)
#   KEEP_WORK=0       1: keep the temp build/run dir
#   TMPDIR            parent dir of the temp build/run dir (default: /tmp)
#
# Notes:
#   - Percentages are shares of the *sampled self time inside the bench
#     executable* (see LINK_MODE for what is not sampled), covering the whole
#     process (load + compile). Caps include the load time.
#   - Library code (libc, libstdc++) is not compiled with -pg: it gets samples
#     but no call counts, and calls made from it are not counted either.
#   - cpu_s - sampled_s = unsampled shared-library time + the -pg overhead
#     itself (mcount samples are excluded by gprof).
#   - Call counts within a wall-clock cap depend on machine load; compare
#     percentages, and cpu_s vs wall time to judge contention.

set -u

# name | gadget file | cap (s) | query | bench options
PROFILE_SET=(
    "vulnserver_load|vulnserver_3.txt|120|eax = [ebx + 4]|--unsafe"
    "efssetup_load|efssetup.txt|45|eax = [ebx + 4]|--unsafe"
    "efssetup_add|efssetup.txt|45|eax = ebx + ecx|--unsafe"
    "mp3conf_add|mp3_conf.txt|45|eax = ebx + ecx|--unsafe"
    "efssetup_add_badbytes|efssetup.txt|45|eax = ebx + ecx|--unsafe --bad-bytes 00,0a,0d"
)

die(){ echo "profile.sh: $*" >&2; exit 1; }

if [ $# -ne 2 ]; then
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 1
fi

SRC=$(cd "$1" 2>/dev/null && pwd) || die "no such source tree: $1"
mkdir -p "$2" || die "can't create output dir: $2"
OUT=$(cd "$2" && pwd)
TOOLS="$(cd "$(dirname "$0")" && pwd)/gprof_tools.py"
JOBS=${JOBS:-2}
RUNS=${RUNS:-}
LINK_MODE=${LINK_MODE:-dynamic}
GPROF_FIX=${GPROF_FIX:-1}
KILL_GRACE=${KILL_GRACE:-30}
GADGETS_DIR=${GADGETS_DIR:-$SRC/samples/gadgets}
KEEP_WORK=${KEEP_WORK:-0}

case "$LINK_MODE" in
    dynamic)    LINK_LDFLAGS="" ;;
    static-cxx) LINK_LDFLAGS="-static-libstdc++ -static-libgcc" ;;
    static)     LINK_LDFLAGS="-static" ;;
    *) die "LINK_MODE must be dynamic, static-cxx or static" ;;
esac
for f in Makefile libropium tests/bench/bench.cpp; do
    [ -e "$SRC/$f" ] || die "$SRC/$f not found"
done
[ -d "$GADGETS_DIR" ] || die "gadget dir not found: $GADGETS_DIR"
[ -f "$TOOLS" ] || die "$TOOLS not found"
for tool in gprof timeout make g++ python3 tar objcopy nm; do
    command -v "$tool" > /dev/null || die "$tool not found"
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/ropium-profile.XXXXXX") || die "mktemp failed"
cleanup(){
    if [ "$KEEP_WORK" = 1 ]; then
        echo "work dir kept: $WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

mkdir -p "$OUT/raw"
rm -f "$OUT"/*.stdout "$OUT"/*.stderr "$OUT"/*.flat.txt "$OUT"/*.graph.txt \
      "$OUT"/raw/*.gmon.out "$OUT/gprof.log" "$OUT/runs.raw"

# ---------- 1. Build in a private copy ----------
BUILD=$WORK/build
mkdir -p "$BUILD/bin"
tar -C "$SRC" --exclude='*.o' --exclude='*.gch' -cf - Makefile libropium tests/bench \
    | tar -C "$BUILD" -xf - || die "copy of $SRC failed"

# Don't let stray CFLAGS/CXXFLAGS/LDFLAGS from the environment change the build
MAKE_CMD=(env -u CFLAGS -u CXXFLAGS -u LDFLAGS -u LDLIBS)
if [ -n "$LINK_LDFLAGS" ]; then
    MAKE_CMD+=(LDFLAGS="$LINK_LDFLAGS")
fi
MAKE_CMD+=(make -C "$BUILD" -j"$JOBS" PROFILE=1 BINDINGS=0 bench)

echo "[*] building profiling bench from $SRC (log: $OUT/build.log)"
"${MAKE_CMD[@]}" > "$OUT/build.log" 2>&1 || die "build failed, see $OUT/build.log"
BENCH=$BUILD/bin/bench
[ -x "$BENCH" ] || die "build produced no $BENCH"
cp "$BENCH" "$OUT/raw/bench"

# Copy of the binary used only by gprof (clone symbols renamed)
GPROF_BIN=$BENCH
if [ "$GPROF_FIX" = 1 ]; then
    if python3 "$TOOLS" clone-map "$BENCH" "$WORK/clone.map" \
        && objcopy --redefine-syms="$WORK/clone.map" "$BENCH" "$WORK/bench.gprof"; then
        GPROF_BIN=$WORK/bench.gprof
    else
        echo "    warning: clone symbol renaming failed, using the plain binary" >&2
    fi
fi

{
    echo "date:        $(date -Is)"
    echo "src_tree:    $SRC"
    echo "src_rev:     $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo n/a)"
    echo "src_dirty:   $(git -C "$SRC" status --porcelain -- Makefile libropium tests/bench 2>/dev/null | wc -l) changed file(s) in Makefile/libropium/tests/bench"
    echo "gadgets_dir: $GADGETS_DIR"
    echo "build:       ${MAKE_CMD[*]}"
    echo "link_mode:   $LINK_MODE"
    echo "gprof_fix:   $GPROF_FIX"
    echo "kill_grace:  $KILL_GRACE"
    echo "compiler:    $(g++ --version | head -n1)"
    echo "gprof:       $(gprof --version | head -n1)"
    echo "kernel:      $(uname -sr)"
    echo "nproc:       $(nproc)"
    echo "uptime:      $(uptime)"
    echo "memory (MB):"
    free -m
} > "$OUT/env.txt"

# ---------- 2./3. Profile runs (serial) ----------
for entry in "${PROFILE_SET[@]}"; do
    IFS='|' read -r name gfile cap query opts <<< "$entry"
    if [ -n "$RUNS" ] && [[ " $RUNS " != *" $name "* ]]; then
        continue
    fi
    read -r -a OPTS <<< "$opts"
    RUN=$WORK/run_$name
    mkdir -p "$RUN"

    echo "[*] $name: $gfile '$query' $opts (cap ${cap}s)"
    load_before=$(cut -d' ' -f1 /proc/loadavg)
    t0=$(date +%s.%N)
    ( cd "$RUN" && export TMPDIR="$RUN" && exec timeout -s INT -k "$KILL_GRACE" "$cap" \
        "$BENCH" "$GADGETS_DIR/$gfile" "$query" "${OPTS[@]}" ) \
        > "$OUT/$name.stdout" 2> "$OUT/$name.stderr"
    rc=$?
    t1=$(date +%s.%N)
    load_after=$(cut -d' ' -f1 /proc/loadavg)

    : > "$OUT/$name.flat.txt"
    : > "$OUT/$name.graph.txt"
    if [ -s "$RUN/gmon.out" ]; then
        cp "$RUN/gmon.out" "$OUT/raw/$name.gmon.out"
        GMON=$RUN/gmon.out
        if [ "$GPROF_FIX" = 1 ] && python3 "$TOOLS" fix-gmon "$RUN/gmon.out" "$RUN/gmon.fixed"; then
            GMON=$RUN/gmon.fixed
        fi
        gprof -b -p "$GPROF_BIN" "$GMON" > "$OUT/$name.flat.txt" 2>> "$OUT/gprof.log"
        gprof -b -q "$GPROF_BIN" "$GMON" > "$OUT/$name.graph.txt" 2>> "$OUT/gprof.log"
        if [ "$GPROF_BIN" != "$BENCH" ]; then
            python3 "$TOOLS" demangle "$OUT/$name.flat.txt" "$OUT/$name.graph.txt"
        fi
    else
        echo "    no gmon.out written (rc=$rc)"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$gfile" "$cap" "$query" "$opts" "$rc" "$t0" "$t1" "$load_before" "$load_after" \
        >> "$OUT/runs.raw"
    rm -rf "$RUN"
done
[ -s "$OUT/runs.raw" ] || die "no run selected (RUNS='$RUNS')"

# ---------- 4. Summary ----------
# runs.raw is kept so that 'gprof_tools.py summary <out_dir>' can re-generate it
python3 "$TOOLS" summary "$OUT" || die "summary failed"
echo "[*] summary: $OUT/summary.md"
