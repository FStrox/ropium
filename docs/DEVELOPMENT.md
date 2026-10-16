# Developing ROPium

How to build, run, test and benchmark ROPium from a source checkout. For the architecture, read
[HOW_IT_WORKS.md](HOW_IT_WORKS.md); for known bugs, [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

## Prerequisites

- `g++` (C++11), `make`
- Capstone with headers (`libcapstone-dev`)
- Python 3 with headers (`python3-dev`) for the bindings, and `prompt_toolkit` for the CLI
- Optional: `ROPgadget` on `PATH` (for `load()`), `gprof` (profiling), `pexpect` (driving the CLI in scripts)

## Build

```bash
make -j4          # bin/libropium.so, bin/tests and the Python module bin/ropium.so
```

| Target | Output |
|---|---|
| `all` (default) | `lib tests bindings` |
| `lib` | `bin/libropium.so` |
| `tests` | `bin/tests` (unit tests) |
| `bindings` | `bin/ropium.so` (self-contained: it links the library objects, not `libropium.so`) |
| `bench` | `bin/bench`, the profiling driver (`make PROFILE=1 BINDINGS=0 bench`) |
| `install` | library, `ropium.hpp`, Python module and CLI (see below) |
| `test` | runs `bin/tests` (doesn't build) |
| `clean` | removes objects and `bin/*` |

| Knob | Effect |
|---|---|
| `DEBUG=1` | `-g -O0` (but see the `python3-config` note below) |
| `BINDINGS=0` | don't build the Python module |
| `PROFILE=1` | `-pg` for gprof |
| `OPT=3`, `LTO=1`, `NATIVE=1` | opt-in `-O3`, `-flto=auto`, `-march=native`. Measured on the corpus, they change little: `OPT=3 LTO=1` was 6 % faster on one long search and flat or slightly slower elsewhere; `NATIVE=1` was slower on a QEMU vCPU. |

**Build gotchas:**

- **No dependency tracking.** Objects depend only on their `.cpp`. After editing a header, or switching
  any knob above, run `make clean` before `make`, otherwise the build silently mixes objects compiled
  against different class layouts or flags.
- `tests` and `bindings` are also directory names, so make may consider them up to date. `make clean && make`
  avoids it.
- With bindings, `python3-config --cflags` is appended to every C++ compile. It ends with `-O2` and adds
  `-g -DNDEBUG`, so `DEBUG=1` is effectively `-O2` for C++, and `BINDINGS=0` builds lose `-DNDEBUG` (asserts
  become active).
- Pass extra flags through the environment, not the command line: `CXXFLAGS="-fsanitize=address" make`
  appends to the Makefile's flags, while `make CXXFLAGS=...` replaces them all (and loses `-std=c++11`).

## Run from the checkout

No installation is needed:

```bash
python3 examples/showcase.py                   # compiles the README showcase queries
PYTHONPATH=bin python3 cli-tool/ropium          # interactive CLI
PYTHONPATH=bin python3 -c "from ropium import *; print(ROPium(ARCH.X86))"
```

`load_rp()` writes `./ropium_raw_gadgets.0` into the current directory, and `load()` writes `.ropium_*`
temp files there. Run scripts from a scratch directory, not the repository root. The repository root may
also contain a stray empty `ropium/` directory (a Docker mount leftover), which Python would import as an
empty namespace package instead of the module.

## Install

```bash
make install PREFIX=$HOME/.local     # recommended: no sudo, everything for the current user
```

This installs `$PREFIX/bin/ropium`, `$PREFIX/lib/libropium.so`, `$PREFIX/include/ropium.hpp`, and the Python
module into the **current user's** site-packages (`python3 -m site --user-site`). `ropium` must then be on
`PATH` (`~/.local/bin` usually is).

Don't use `sudo make install` unless only root will use ROPium: the module would go to root's site-packages,
and a normal user's `ropium` CLI would fail with `ModuleNotFoundError`.

## Unit tests

```bash
./bin/tests                      # all suites (~15 s, almost all of it "compiler")
./bin/tests db strategy compiler # only these suites
```

Suites: `expr simp ir gadgets db strategy il compiler`. Unknown names are skipped with exit status 0. The
process exits 1 at the first failed assertion.

- The `gadgets` suite currently tests nothing (0/0) and writes to `/tmp`.
- The lifter and the symbolic engine have no unit tests; the corpus fixture is what covers them.
- When you add a test for a bug, check that it **fails** without the fix (revert the fix in a scratch
  copy, or temporarily) before relying on it.

## Corpus fixture (chain regression)

`tests/perf_baseline.py` runs a fixed matrix of 120 cases:

- 3 gadget files: `vulnserver_3`, `efssetup`, `mp3_conf`;
- 5 settings: default, bad bytes `00 0a 0d`, keep `esi edi`, `safe_mem = False`, bad bytes
  `0a 0d 20 25 2f 5c`;
- 8 queries.

Each case runs in a fresh Python subprocess, in its own temporary directory, with a CPU-time cap.
`tests/perf_baseline.json` holds the reference outcome (FOUND / NONE / TIMEOUT) and the raw chain bytes,
captured from master `98e1996`.

```bash
python3 tests/perf_baseline.py verify --skip-timeouts --jobs 3     # ~2 min: outcomes + byte-identical chains
python3 tests/perf_baseline.py deadline --rop-timeout 2            # every compile() returns within 2 s + 100 ms
python3 tests/perf_baseline.py list --perf-subset                  # the 18 cases used for timing
python3 tests/perf_baseline.py timing --label mine --out /tmp/timing.json
```

- `verify` prints `RESULT: OK` or `RESULT: FAIL`. Baseline TIMEOUT cases are informational (`--skip-timeouts`
  skips them; several now finish).
- Never re-capture the fixture to make a diff go away: a chain that changes means the search changed. The
  only legitimate reasons are an intended behavior change or a bug fix, which must be explained. `capture`
  refuses to overwrite the fixture without `--force`.
- The fixture records the behavior of master `98e1996`, bugs included: the two `efssetup|...|[eax + 8] = ebx`
  reference chains use a mis-analysed `pushal` gadget ([KNOWN_ISSUES 1.1](KNOWN_ISSUES.md#1-chains-that-are-wrong-at-runtime)).
  A fix for that issue is expected to change them.
- `timing` without `--out` writes its results **into the tracked fixture**; pass `--out`.
- Compare compile **CPU** seconds (the fixture records both): wall time is unreliable on a busy machine.

## Profiling

```bash
tests/bench/profile.sh . /tmp/profile-out     # builds a private PROFILE=1 copy, runs 5 capped profiles
less /tmp/profile-out/summary.md
```

- `profile.sh` never touches your `bin/` or objects. It runs 5 fixed profiles (vulnserver, efssetup and
  mp3_conf queries), each capped with `timeout -s INT`, and writes gprof flat and call-graph outputs plus a
  summary.
- Knobs: `RUNS="efssetup_load ..."`, `JOBS`, `LINK_MODE=dynamic|static-cxx|static` (static makes libc and
  libstdc++ visible to gprof), `KEEP_WORK=1`.
- `tests/bench/gprof_tools.py` corrects two gprof attribution artifacts and regenerates summaries.
- `bin/bench <gadget file> <query> [--unsafe] [--bad-bytes 00,0a] [--keep-regs esi,edi] [--os linux] [--arch x86|x64]`
  runs one load + compile and prints `load_s`, `compile_s`, the result and `cpu_s`. Build it with
  `make PROFILE=1 BINDINGS=0 bench` (or without `PROFILE=1` for timing).

`-pg` instruments every call, so it overstates call-heavy code: use profiles for shares and the `timing`
subcommand for speed.

## Sanitizers

Build a separate copy so your normal objects aren't mixed with sanitized ones:

```bash
git worktree add /tmp/ropium-asan HEAD && cd /tmp/ropium-asan
CXXFLAGS="-fsanitize=address -fno-omit-frame-pointer -g" CFLAGS="-fsanitize=address -g" \
LDFLAGS="-fsanitize=address" make -j4 BINDINGS=0 tests bench
ASAN_OPTIONS=detect_leaks=1 ./bin/tests
```

`bin/bench` leaks the gadget database on purpose (it exits right after the search), so LeakSanitizer reports
loading memory there. Look for leaks whose stacks contain `StrategyGraph`, `CompilerTask` or `ROPChain`.

## Changing the search

The search must stay deterministic and exact; [HOW_IT_WORKS §15](HOW_IT_WORKS.md#15-rules-for-changing-the-search)
lists the rules. A typical check before committing a search change:

1. `make clean && make -j4 && ./bin/tests`
2. New unit test that fails without the change (mutation check)
3. `python3 tests/perf_baseline.py verify --skip-timeouts`: 113/113 PASS
4. `python3 tests/perf_baseline.py deadline --rop-timeout 2` (and a larger timeout such as 10 if you touched
   anything the search loops over)
5. Timing of the perf subset against the previous build (CPU seconds, serial, quiet machine)
6. ASan build of the unit tests

## Docker

The `Dockerfile` builds an image whose entrypoint is the CLI (`docker run -it ropium`). It removes the
compiler after building, so it isn't a development environment: rebuild the image after changing the code.
