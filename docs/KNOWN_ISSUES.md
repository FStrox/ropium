# Known issues

This page lists the bugs and limitations found during a full code review of the `perf/ropchain-performance`
branch (October 2026, HEAD `9f5b279`). None of them is fixed yet. Each entry gives the location and how it
was confirmed:

- **reproduced**: run against the built library or Python module, on the bundled samples or on a small
  hand-made gadget file;
- **code**: found by reading the code, not exercised.

Line numbers refer to that commit. For how the components fit together, see [HOW_IT_WORKS.md](HOW_IT_WORKS.md).

## Contents

- [1. Chains that are wrong at runtime](#1-chains-that-are-wrong-at-runtime)
- [2. Crashes](#2-crashes)
- [3. Silent failures and misleading results](#3-silent-failures-and-misleading-results)
- [4. Gadgets the analysis can't use](#4-gadgets-the-analysis-cant-use)
- [5. Query language and compiler limitations](#5-query-language-and-compiler-limitations)
- [6. Python API and CLI quirks](#6-python-api-and-cli-quirks)
- [7. Build, install, Docker and tests](#7-build-install-docker-and-tests)
- [8. Internal code issues](#8-internal-code-issues)

---

## 1. Chains that are wrong at runtime

These are the most serious: `compile()` returns a chain, but the chain doesn't do what the query asks.
Check chains before relying on them, especially when they involve the gadget shapes below.

| # | Issue | Where | Status |
|---|---|---|---|
| 1.1 | **Reads of stack slots written by the same gadget are mis-modelled.** Symbolic memory matches a read to an earlier write by `Expr` *pointer*, not by address value, so a read through a recomputed address misses the write. `pushal ; pop ebx ; ret` is accepted as `ebx = edi` with a normal `ret`, but its `ret` really jumps to the saved `esi`. `mov [esp+4], eax ; pop ecx ; pop edx ; ret` is filed as a pop into `edx`, although `edx` gets `eax`. The shipped `efssetup.txt` contains two such `pushal` gadgets (0x407d7b, 0x407d7c) and `ImageLoad.txt` one (0x10003588). The reference chains of the fixture cases `efssetup\|default\|[eax + 8] = ebx` and `efssetup\|badbytes_nonull\|[eax + 8] = ebx` use one, so they are wrong. | `ir.hpp:191`, `ir.cpp:408-436` | reproduced |
| 1.2 | **A RET gadget may take its return address from below the entry stack pointer.** The RET rule checks `c + word == sp_inc` but not `c >= 0`, so a negative `sp_inc` RET gadget (1.1) is accepted, and the chain gets no padding for it. Negative `sp_inc` must stay legal for `call reg` JMP gadgets. Proposed fix for 1.1 + 1.2: key `MemContext::writes` by structure (`e->hash()` / `a->eq(b)`) and require `c >= 0` in the RET rule. A scratch build of that fix turned the 3 sample `pushal` gadgets into correct `JMP esi` gadgets and passed all unit tests. | `database.cpp:224-227` | reproduced |
| 1.3 | **A store's address register isn't protected.** `is_final_param` treats the address register of a STORE/ASTORE as an output, so scheduling puts a gadget that clobbers it *before* the store. With `mov [eax+8], ecx; ret` and `mov ecx, ebx; xor eax, eax; ret`, `[eax+8] = ebx` returns a chain that writes to address 8. | `strategy_graph.cpp:58-62, 1118-1120` | reproduced |
| 1.4 | **The source register of `reg = reg OP cst` isn't protected.** `il_to_strategy` doesn't mark it as a data link, so `eax = ebx + 4` can return a chain that zeroes `ebx` before the `lea`. Other forms miss the flag too (the MOV_CST of `[cst]` loads/stores, the address of `[reg+off] = cst`). | `compiler.cpp:1071` (and 1137, 1165, 1214, 1266, 1284) | reproduced (1071), code (others) |
| 1.5 | **Register permutations protect the wrong registers.** When syscall or x64 call arguments are set in a non-default order, the keep-register loop reads `instr[j]` instead of `instr[permutation[j]]`. `sys_1(rsi, 2)` can return a chain that sets `rdi = 2`. The failed-prefix list also mixes register numbers into a list of instruction indices. | `compiler.cpp:387-391, 402-405` | reproduced (first), code (second) |
| 1.6 | **x86 syscalls by name use the x64 numbers.** `get_syscall_def(ArchType::X64, …)` is used for x86, so `sys_execve(…)` loads `eax = 0x3b` (x64 execve) instead of 11, and x86-only names are refused. The x86 table is never used. Use the numeric form (`sys_0xb(…)`) on x86. | `compiler.cpp:808`, `systems.cpp:7-57` | reproduced |
| 1.7 | **X64_MS calls use the wrong registers and no shadow space.** Arguments go to RDX, RCX, R8, R9 (Microsoft x64 is RCX, RDX, R8, R9), and the 5th argument is placed right after the return address, with no 32-byte shadow space. | `compiler.cpp:691` | reproduced |
| 1.8 | **String stores corrupt bytes ≥ 0x80 and write past the string.** Characters are sign-extended (`'a\x80'` is stored as `0xfffe8061`), and the last partial word is padded with `0xff`, so `'abcde'` writes 8 bytes. | `compiler.cpp:932-961` | reproduced |
| 1.9 | **Mislifted instructions.** SSE `movsd`/`cmpsd` share Capstone ids with the string instructions and get string semantics; `rep stos*` runs once and leaves `ecx` alone; `push esp` pushes the decremented value; x86 `rdtsc` puts the whole TSC in both `eax` and `edx`. | `archX86.cpp` (5803, 5848, stos handlers, 4000-4018, 4227-4239) | reproduced |
| 1.10 | **Lines of a program are compiled independently.** A later line may clobber a register set by an earlier one (`eax = 1\nebx = 2` can end with `eax = 0` if the `ebx` gadget does `xor eax, eax`). Only `keep_regs` is honoured across lines. | `compiler.cpp:229-258` | reproduced |

## 2. Crashes

These kill the Python interpreter or the CLI.

| # | Issue | Where | Status |
|---|---|---|---|
| 2.1 | `compile('')`, a whitespace-only query or `'\n'` segfaults: `_compile` reads `instr[0]` of an empty vector. | `compiler.cpp:216` | reproduced |
| 2.2 | A gadget address ≥ `0x80000000` aborts the process (`std::stoi` throws `std::out_of_range`, which nothing catches). This makes most x64 targets and high-loaded x86 images unusable. | `utils.cpp:47` | reproduced |
| 2.3 | `del rop.bad_bytes` (also `keep_regs`, `safe_mem`, `abi`, `os`) segfaults: the setters don't handle deletion. | `py_ropium.cpp:179-332` | reproduced |
| 2.4 | `1 + chain` segfaults (`nb_add` doesn't check the type of its left operand). `chain + 1` correctly raises `TypeError`. | `py_ropchain.cpp:143-151` | reproduced |
| 2.5 | Chains borrow the `Arch` and gadgets of their `ROPium` object. After `del rop`, printing a chain shows corrupted text (use-after-free). Keep the `ROPium` object alive. | `py_ropchain.cpp` | reproduced |
| 2.6 | CLI: `load_rp -a x86` (lower case, as its help suggests) raises `KeyError`; `keepregs set rax` in an x86 session crashes the next `find`; a `RuntimeError` from `load` is not caught. | `cli-tool/ropium:206-208, 305-309` | reproduced |
| 2.7 | `BadBytes::get_valid_byte()` loops forever when all 256 bytes are bad (`unsigned char byte >= 0` is always true). | `constraint.cpp:21-28` | code |

## 3. Silent failures and misleading results

| # | Issue | Where | Status |
|---|---|---|---|
| 3.1 | `load()` without `ROPgadget` on `PATH`, or on a non-binary file, "succeeds" with **0 gadgets** (only `sh: ROPgadget: not found` on stderr). The CLI then prints `[+] Loaded`. | `utils.cpp:89-142` | reproduced |
| 3.2 | `load_rp()` on a UTF-16 file (what PowerShell's `>` writes) loads **0 gadgets** or fails with a misleading `Couldn't read input file`; a single invalid UTF-8 byte fails the whole file the same way. Convert with `iconv -f utf-16 -t utf-8` first. | `utils.cpp:151-206` | reproduced |
| 3.3 | `compile()` returns `None` for four different reasons: no chain within the budget, timeout, Ctrl+C, or an empty database. Only `rop.timed_out` tells one of them apart. Ctrl+C makes the CLI print `No ROPChain found.` | `py_ropium.cpp:127-151` | reproduced |
| 3.4 | Ctrl+C aborts only the current search task: a syscall or x64 call (one task per register) keeps going until the next task, or until its timeout. | `compiler.cpp:86-111` | reproduced |
| 3.5 | `dump('python')` isn't valid Python 3 (`p = ''` then `p += pack(...)` mixes `str` and `bytes`) and contains ANSI color codes unless `color=False` is passed. Use `dump('raw')` for payloads. | `ropchain.cpp:51-85` | reproduced |
| 3.6 | `dump(<unknown format>, '', False)` raises before re-enabling colors, so colors stay off process-wide. `str(chain)` always uses colors. | `py_ropchain.cpp:59-62` | reproduced |
| 3.7 | If the first line of a program is a syscall or an x64 call, the following lines are silently dropped; a syscall after a simple line raises `RuntimeError`. | `compiler.cpp:176-185, 216` | reproduced |
| 3.8 | `ROPgadget`'s binary path is passed to the shell unquoted: paths with spaces break, and shell metacharacters are interpreted. | `utils.cpp:97` | code |
| 3.9 | `load_rp()` always uses `./ropium_raw_gadgets.0` in the current directory (two processes in one directory collide) and leaves it behind on errors. Both loaders print progress lines on stdout. | `py_ropium.cpp:94-116` | reproduced |

## 4. Gadgets the analysis can't use

Gadgets in these categories are dropped (or never selected), so a chain that a human could build may not be
found. See [HOW_IT_WORKS.md §5-6](HOW_IT_WORKS.md#5-lifting-bytes-to-ir).

| # | Issue | Where | Status |
|---|---|---|---|
| 4.1 | **Conditions are never constant-folded before a branch.** Every internal branch must be a literal constant, and `1 & 0x3f` stays an AND node. So shifts and rotates (even with an immediate count), `cmov`, `setcc`, `movsx`, `cdqe`/`cqo`, `cpuid`, `cmpxchg`, `bsf`/`bsr`, conditional jumps and string instructions without a preceding `cld`/`std` all fail. Simplifying the condition before the check would likely fix most of them. | `symbolic.cpp:272, 285` | reproduced |
| 4.2 | Unsupported instructions drop the gadget: `sbb`, `endbr64`/`endbr32` (so CET binaries lose every gadget with `endbr64`), `pushf`/`popf`, `shld`/`shrd`, `sahf`, `loop`, `retf`/`iret`, `lzcnt`/`tzcnt`/`popcnt`, BMI2 shifts, FPU/MMX/SSE/AVX. | `archX86.cpp:5742-5961` | reproduced |
| 4.3 | `ret imm16` gadgets are always rejected (the return address must be the last stack slot read). | `database.cpp:222-235` | reproduced |
| 4.4 | Every *intermediate* stack-pointer value must be `sp0 ± k·word`, so `leave; ret`, `pop esp`, `xchg esp, eax` and `push word` gadgets are dropped. | `symbolic.cpp:332-355` | reproduced |
| 4.5 | `jmp [reg]`, `call [reg]` and direct jumps are rejected; only `ret`, `jmp reg`/`call reg`, `syscall`/`sysenter` and `int 0x80` end a usable gadget. | `database.cpp:209-236` | reproduced |
| 4.6 | `int 0x80` gadgets are classified but never used: the compiler only builds SYSCALL nodes (`syscall`/`sysenter`). | `strategy_graph.cpp`, `compiler.cpp` | reproduced |
| 4.7 | Subtraction-based gadgets (`sub eax, ebx`, `sub eax, [m]`, `sub [m], eax`) are never classified, because the simplifier rewrites them as `(-1*b)+a`. | `database.cpp:40-128` | reproduced |
| 4.8 | The simplifier isn't a real fixpoint: `pop ebx; mov eax, [esp+8]` leaves the address as `((0x8+0x8)+esp)`, which doesn't match the load pattern, so the load isn't classified. | `simplification.cpp:37-77` | reproduced |
| 4.9 | A wider read after a narrower write takes the missing high part at `addr + <bit size>` instead of `addr + <byte size>`. | `ir.cpp:431` | reproduced |
| 4.10 | On x64, `mov eax, ebx` produces `rax = {0, rbx[31:0]}`, which matches no table, so 32-bit moves are not usable as register moves. | `database.cpp:56-103` | code |
| 4.11 | `syscall` under `ARCH.X86` is rejected (only `sysenter` counts); `sysenter` under X64 is rejected. | `archX86.cpp:5566-5600` | reproduced |

## 5. Query language and compiler limitations

| # | Issue | Where | Status |
|---|---|---|---|
| 5.1 | There is no binary `-` operator: `eax = ebx - 3` and every `-=` form are rejected. Write `eax = ebx + -3`. | `il.cpp:345-373` | reproduced |
| 5.2 | `reg OP= cst` and `reg OP= reg` (e.g. `eax *= 2`, `eax += ebx`) are rejected; `OP=` only works with a memory operand. | `il.cpp` | reproduced |
| 5.3 | Registers are lower case only; there is no `;` separator; unary `~`/`-` on registers isn't supported; `rt_sigaction`/`rt_sigreturn` can't be parsed (names may only contain letters and digits); the x64 table declares `close` with 2 arguments and spells `rcvfrom`. | `il.cpp`, `systems.cpp:63, 77` | reproduced |
| 5.4 | Zero-argument x64 function calls always return `None`. | `compiler.cpp:662-666, 772-776` | reproduced |
| 5.5 | Register permutations grow as n!: `sys_mmap` with 6 arguments hit a 5 s timeout on `vulnserver_3`. | `compiler.cpp:366-451` | reproduced |
| 5.6 | `mov_cst_pop` drops a node's `mandatory_following_node` and constraints; `generic_transitivity` moves paddings to the first node while their `sp_inc` dependencies move to the second. Effect on function calls not confirmed. | `strategy_rules.cpp:13-171` | code |
| 5.7 | `_compile` permanently adds the stack pointer to the caller's safe-register set (it mutates the Python object's constraint). | `compiler.cpp:213` | code |

## 6. Python API and CLI quirks

| # | Issue | Where | Status |
|---|---|---|---|
| 6.1 | `ROPium` is a factory function, not a class; the chain type isn't exported. | `py_module.cpp`, `py_ropchain.cpp` | reproduced |
| 6.2 | `dump()` arguments are positional-only (`dump(fmt='raw')` raises `TypeError` despite the docstring). | `py_ropchain.cpp:28-69` | reproduced |
| 6.3 | `rop.abi` and `rop.os` accept any integer; `bad_bytes` and `keep_regs` accept only lists, and clear the old value *before* validating, so a rejected assignment still empties the setting. | `py_ropium.cpp:161-332` | reproduced |
| 6.4 | `rop.timeout = 0` means "no limit", while the CLI's `timeout set 0` is rejected. | `py_ropium.cpp:362-401` | reproduced |
| 6.5 | CLI `find` removes every space from the query (it joins its arguments without a separator), including spaces inside string literals. | `cli-tool/ropium:304` | reproduced |
| 6.6 | CLI `badbytes set` parses each byte as decimal first, then hex: `10` is `0x0a`, `ff` is `0xff`. Use the `0x` prefix to be unambiguous. | `cli-tool/ropium:346-353` | reproduced |
| 6.7 | CLI `help os` and `help load_rp` print the main help; stdin redirected from a regular file (`< cmds.txt`) hits EOF immediately (pipes and ptys work). | `cli-tool/ropium:106-124` | reproduced |
| 6.8 | `py_arch.cpp` builds the `X86` and `X64` classes from an already-released dict; it works only because CPython reuses the memory. | `py_arch.cpp:69, 116` | code |
| 6.9 | The search deadline, the SIGINT handler and the color switch are process-wide, and `compile()` holds the GIL; one search runs at a time per process. | `utils.cpp`, `compiler.cpp` | code |

## 7. Build, install, Docker and tests

| # | Issue | Where | Status |
|---|---|---|---|
| 7.1 | No header or flag dependency tracking: after editing a header, or switching `DEBUG`/`PROFILE`/`BINDINGS`/`OPT`/`NATIVE`/`LTO`, run `make clean` or the build silently mixes old and new objects. | `Makefile` | code |
| 7.2 | The `tests` and `bindings` targets share their names with directories, so make may consider them up to date while `bin/tests`/`bin/ropium.so` are stale or missing. `make clean && make` avoids it. | `Makefile` | reproduced |
| 7.3 | `make install` puts the Python module in the site directory of the user *running make*: under `sudo` that is root's, and the user's `ropium` CLI then fails with `ModuleNotFoundError`. Use `make install PREFIX=$HOME/.local` without `sudo`. | `Makefile:133-152` | reproduced |
| 7.4 | The installed header `ropium.hpp` includes `memory.hpp`, which doesn't exist, and none of the headers it includes are installed. | `libropium/include/ropium.hpp:8` | reproduced |
| 7.5 | `make test` only runs `bin/tests`; it doesn't build first. | `Makefile:174-175` | code |
| 7.6 | `BINDINGS=0` builds lose `-DNDEBUG` and `-g` (both come from `python3-config --cflags`), so `assert()`s become active. With bindings, `DEBUG=1` is effectively `-O2` for C++ for the same reason. | `Makefile` | code |
| 7.7 | The Docker image installs the CLI as its entrypoint and removes `g++`, so it can't rebuild ROPium inside the container. | `Dockerfile` | code |
| 7.8 | The `gadgets` unit suite has no assertions (it always reports 0/0), writes to `/tmp`, and reads a different file than it writes. The lifter and the symbolic engine have no unit tests; `test_simplification.cpp` enables a rule (`es_deep_associative`) that production doesn't use; two strategy tests are commented out. | `tests/` | reproduced |
| 7.9 | `RopChainer.py` doesn't run: it imports `ropium` before adding `./bin` to `sys.path`, needs ROPgadget, and doesn't handle `None`. Use `examples/showcase.py`. | `RopChainer.py` | reproduced |
| 7.10 | `tests/perf_baseline.py timing` without `--out` writes its results into the tracked fixture `tests/perf_baseline.json`. | `tests/perf_baseline.py` | code |

## 8. Internal code issues

Not visible to users today, but worth knowing before changing the code.

- **Equality is a 32-bit hash comparison** (`expression.cpp:80`): any two `UNKNOWN` expressions of the same
  size are "equal", and different node kinds can collide.
- **The simplifier mutates shared nodes in place** (`simplification.cpp:56-63`) and resets only that node's
  hash, so ancestors keep stale hashes. Brace and typo bugs make parts of three rules dead code
  (`es_arithmetic_properties`, `es_concat_patterns`, `es_arithmetic_factorize`).
- **Memory operands are ordered by heap address** when canonicalising (`expression.cpp:89`), so canonical
  forms can depend on allocation.
- `ExprVar::copy()` drops the register number; `replace_var_name()` renames in place without resetting the
  hash or the concretization cache (`expression.cpp:119-141, 203-210`).
- Exceptions: `analyse_raw_gadgets` catches only two exception types around symbolic execution
  (`database.cpp:162-170`), and the bindings catch only three, so any other C++ exception aborts the load
  or the interpreter.
- Leaks: the `IRBlock` of every rejected gadget, and engine state on expression-construction errors.
- Dead or unused: `ILInstructionType::JMP`, `_parse_il_unop`, the x86 syscall table, the `jmp` table and
  `get_possible_jmp`, `Gadget::bin_num`/`_hex_str`, `IRBlock::branch_target`, `dfs_strategy` (printing
  only); `IRBlock::raw_size` is computed backwards.
- `Gadget::jmp_reg` is uninitialized for non-JMP gadgets; `RawGadget`'s default constructor leaves `addr`
  uninitialized.
- Rejected byte strings are re-lifted every time they occur (only accepted gadgets are deduplicated).
