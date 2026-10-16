# ROPium internals: how it works

This document explains how ROPium works, end to end, for people who want to change it or understand why it
returns a given chain. For using ROPium, read the [README](../README.md). For building, testing and
benchmarking, read [DEVELOPMENT.md](DEVELOPMENT.md). Known bugs are tracked in [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

## Contents

1. [Overview](#1-overview)
2. [Repository map](#2-repository-map)
3. [A query from start to finish](#3-a-query-from-start-to-finish)
4. [Gadget ingestion](#4-gadget-ingestion)
5. [Lifting: bytes to IR](#5-lifting-bytes-to-ir)
6. [Symbolic execution](#6-symbolic-execution)
7. [Expressions and simplification](#7-expressions-and-simplification)
8. [Gadget acceptance and classification](#8-gadget-acceptance-and-classification)
9. [Database queries](#9-database-queries)
10. [The query language](#10-the-query-language)
11. [The compiler](#11-the-compiler)
12. [Constraints](#12-constraints)
13. [ROP chains and dump formats](#13-rop-chains-and-dump-formats)
14. [Python bindings and CLI](#14-python-bindings-and-cli)
15. [Rules for changing the search](#15-rules-for-changing-the-search)
16. [Performance notes](#16-performance-notes)

---

## 1. Overview

ROPium is a **ROP-chain compiler**. You describe what a chain must achieve (`eax = 0x1234`,
`[eax - 8] = ebx`, `0x08041234(1, 2)`, ...) and ROPium searches its gadget database for a sequence of
gadgets that does it, under constraints (bad bytes, registers to preserve, memory safety).

```
 binary ──► ROPgadget ─────────┐                           ┌──────────────────────────────────┐
 rp++ / ROPgadget dump file ───┴─► raw gadgets ──────────► │ analysis (per gadget)            │
                                   "addr$hexbytes"         │  Capstone → IR → symbolic exec   │
                                                           │  → accept / reject → classify    │
                                                           └───────────────┬──────────────────┘
                                                                           ▼
                                                              typed gadget database (GadgetDB)
                                                                           │
 query ──► parser (IL) ──► strategy graph ──► search: queue + rewrite rules + gadget selection DFS
 constraints ─────────────────────────────────────────────────────────────┘          │
                                                                                      ▼
                                                                            ROPChain → pretty / raw
```

**The mental model in five sentences.**

1. Every gadget is re-disassembled by ROPium itself and executed symbolically from a fully symbolic state.
   The result is one final expression per register (stack pointer, program counter and flags included)
   plus a map of memory writes.
2. Gadgets whose stack pointer moves by a known amount and that end in a usable branch are filed into
   typed hash tables keyed by what they compute, e.g. "`ecx` ← `eax`".
3. A query becomes a small **strategy graph**: abstract gadget slots whose parameters are fixed by the
   query, free (to be chosen), or dependent on other slots.
4. The compiler tries graphs smallest-first. For each one, a backtracking search assigns real gadgets to
   the slots. When it fails, six **rewrite rules** produce slightly larger alternative graphs (go
   through a scratch register, pop the constant from the stack, ...).
5. Everything is deterministic: the same database and query always give the same chain.

## 2. Repository map

| Path | Role |
|---|---|
| `libropium/arch/` | Architectures (`ArchX86`, `ArchX64`) and the Capstone-based lifter (`archX86.cpp`, ~6000 lines). `disassembler.cpp` only holds a destructor. |
| `libropium/ir/` | IR instructions, operands, blocks, and the runtime register/memory contexts (`IRContext`, `MemContext`). |
| `libropium/symbolic/` | Expressions (`expression.cpp`), simplification rules (`simplification.cpp`), symbolic execution (`symbolic.cpp`). |
| `libropium/database/` | `GadgetDB`: gadget analysis, acceptance, classification and queries. |
| `libropium/ropchain/` | `Gadget`, `ROPChain` (dump formats), constraints (`BadBytes`, `KeepRegs`, `MemSafety`), assertions. |
| `libropium/compiler/` | Query parser (`il.cpp`), compiler driver (`compiler.cpp`), strategy graphs and gadget selection (`strategy_graph.cpp`), rewrite rules (`strategy_rules.cpp`), syscall tables (`systems.cpp`). |
| `libropium/utils/` | Gadget file parsers (raw, ROPgadget, rp++), SIGINT handling, the search deadline. |
| `libropium/include/` | All headers. `ropium.hpp` is the umbrella header (currently broken, see [KNOWN_ISSUES 7.4](KNOWN_ISSUES.md#7-build-install-docker-and-tests)). |
| `bindings/` | CPython extension module `ropium` (`bin/ropium.so`). It links the library objects directly. |
| `cli-tool/ropium` | Interactive CLI (Python, prompt_toolkit). |
| `tests/` | Unit tests (`bin/tests`), corpus fixture runner (`perf_baseline.py`, `perf_baseline.json`), profiling harness (`bench/`). |
| `samples/` | Sample PE binaries, gadget dumps (`samples/gadgets/`), and bundled tools. |
| `examples/showcase.py` | Runnable version of the README showcase. |

## 3. A query from start to finish

`ebx = 0xdeadbeef` on `samples/gadgets/vulnserver_3.txt` returns:

```
0x00402673 (pop ebx; pop ebp; ret)
0xdeadbeef
0xffffffff
```

1. **Loading.** `load_rp` turns each line of the dump into a raw gadget (`0x00402673$5b5dc3`). The analysis
   lifts the bytes, executes them symbolically and finds `ebx = mem(esp)`, `ebp = mem(esp+4)`,
   `eip = mem(esp+8)`, `esp = esp+12`. The gadget is a RET gadget with `sp_inc = 12`, filed (among others)
   under `load(ebx, esp, 0)`. **A `pop` is a load from the stack pointer**: there is no "pop" table.
2. **Parsing.** The query becomes one `MOV_CST` IL instruction (`dst = ebx`, `cst = 0xdeadbeef`).
3. **First graph.** `il_to_strategy` builds a one-node graph `MOV_CST ebx ← 0xdeadbeef`. Before searching,
   the early-fail check asks the database whether any gadget sets `ebx` to that exact constant. None does,
   so the graph fails at once, but it still counts as one try and still gets the rewrite rules applied.
4. **Rewrite rules.** Among the new graphs, `mov_cst_pop` yields the smallest: one `LOAD ebx ← [esp + off]`
   node with a free offset `off` and a *special padding* "write `0xdeadbeef` at stack offset `off`". The
   queue pops it first.
5. **Gadget selection.** The node has a free parameter, so the search enumerates
   `get_possible_load(ebx, esp, *)`: the gadget above matches with `off = 0`. The rule's constraints hold
   (`0 ≤ off < sp_inc − 4`), and the padding value has no bad bytes. Scheduling is trivial for one node.
6. **Emission.** The chain gets the gadget's address, then `sp_inc/4 − 1 = 2` stack words: the special
   padding `0xdeadbeef` at offset 0 and the default padding `0xffffffff` at offset 4 (for `pop ebp`). The
   `ret` consumes the next chain item.

The same machinery handles everything else. For example, `ecx = edx` on efssetup has no direct
`mov ecx, edx` gadget, so `generic_transitivity` rewrites it into `R ← edx; ecx ← R` with a free register
`R`. The search finds `R = eax`.

## 4. Gadget ingestion

Every loading path ends in `GadgetDB::analyse_raw_gadgets()`, fed with a list of `RawGadget{raw bytes, address}`.

| Path | Source | Conversion |
|---|---|---|
| `load(binary)` (Python) / `load` (CLI) | A binary | `ropgadget_to_file()` runs `ROPgadget --binary <file> --dump --all --depth 15` through a shell, keeps lines whose first token starts with `0x` and takes the **last token** as the hex bytes. Temp files `.ropium_raw_gadgets.N` and `.ropgadget_output.N` in the current directory. |
| `load_rp(file)` (Python) / `load_rp` (CLI) | A text dump from rp++ (`0x4236a3: aaa ; pop edi ; ret ; \x37\x5f\xc3 (1 found)`) or from `ROPgadget --dump` (`0x00403e23 : aaa ; ret // 37c3`) | `rp_gadgets_to_file()`: per line, drop `(N found)`, trim, split on spaces, require more than 3 tokens and a first token starting with `0x`, take the last token as the bytes and strip `\x`. Headers and banners are skipped this way. Temp file `./ropium_raw_gadgets.0`. |
| Internal format | `<hex address>$<hex bytes>` per line | `raw_gadgets_from_file()`, used by both paths above. |

**Bytes are required.** ROPium never trusts the disassembly text of a dump: it re-disassembles the bytes.
rp++ must be run with `--print-bytes`.

**Limits** (details in [KNOWN_ISSUES](KNOWN_ISSUES.md#3-silent-failures-and-misleading-results)):

- addresses must be below `0x80000000`, because they are parsed with `std::stoi`;
- the file must be UTF-8 (convert UTF-16 rp++ output with `iconv`);
- `load` silently loads nothing when ROPgadget is missing.

## 5. Lifting: bytes to IR

`DisassemblerX86::disasm_block()` (`libropium/arch/archX86.cpp`) decodes one instruction at a time with
Capstone (5.x, detail mode, one preallocated `cs_insn`, so a disassembler is not reentrant) and calls one
`x86_<mnemonic>_d()` handler per instruction. Each handler appends IR instructions to an `IRBlock`.

**End of gadget.** Lifting stops after the first instruction in a Capstone `jump`, `call`, `ret`, `int` or
`iret` group. With Capstone 5, `syscall` and `sysenter` are in the `int` group. Running out of bytes before
such an instruction is an error, so the raw gadget must end with a branch.

**The IR** (`libropium/include/ir.hpp`):

| Category | Operations |
|---|---|
| Arithmetic and logic | ADD, SUB, MUL, MULH, SMULL, SMULH, DIV, SDIV, NEG, AND, OR, XOR, NOT, SHL, SHR, MOD, SMOD |
| Memory | LDM `dst ← mem[src]`, STM `mem[dst] ← src` |
| Data | MOV, CONCAT, BISZ (`dst = (src == 0) ? mode : !mode`) |
| Control | BCC (branch between the IR basic blocks of one instruction), JCC (leave the block: sets PC), INT, SYSCALL |

- **Operands** are constants, architecture registers (VAR, by register number) or block-local temporaries
  (TMP). Each operand is a bit slice `[high:low]`: `ah` is `rax[15:8]`.
- **Every register is a full-width variable**: general-purpose registers, the program counter, segment
  registers, each flag (holding 0 or 1) and the TSC. x86 has 33 registers, x64 has 41.
- **Memory operands** are computed explicitly: `segment + base + index*scale + disp`. A segment register
  is treated as the base address of its segment, so `fs:[0x28]` reads `mem(fs + 0x28)`.
- **Flags** are computed exactly (ZF, SF, CF, OF, AF, PF), so one `add` lifts to about 50 IR instructions.
- **On x64**, writing a 32-bit register zero-extends into the 64-bit register. 8- and 16-bit writes keep
  the other bits.
- **Intra-instruction control flow** (REP loops, `cmov`, `setcc`, shift-count tests, the direction flag)
  is expressed with BCC between IR basic blocks. That matters in the next section.

**Supported instructions** include the usual data movement (`mov`, `movzx`, `lea`, `xchg`, `xadd`,
`push`, `pop`, `pushad`/`popad`, `leave`, `bswap`, ...), arithmetic (`add`, `adc`, `sub`, `inc`, `dec`,
`neg`, `mul`, `imul`, `div`, `idiv`, `cmp`), logic (`and`, `or`, `xor`, `not`, `test`, BMI1), bit tests,
shifts and rotates, `cmovcc`, `setcc`, string instructions, flag instructions, `call`, `jmp`, `jcc`, `ret`,
`int`, `syscall`/`sysenter`. Several of them lift but cannot be executed symbolically (next section).
Unsupported instructions (`sbb`, `endbr64`, `pushf`/`popf`, `shld`/`shrd`, SIMD/FPU, ...) make the gadget
fail to lift. The full list is in [KNOWN_ISSUES §4](KNOWN_ISSUES.md#4-gadgets-the-analysis-cant-use).

## 6. Symbolic execution

`SymbolicEngine::execute_block()` (`libropium/symbolic/symbolic.cpp`) interprets the IR once, from an initial
state where every register is a symbolic variable named after it (`eax`, `esp`, `zf`, ...).

- **Registers** live in an `IRContext` (one expression per register). Values are built with the expression
  operators, which canonicalise but don't simplify (simplification runs at the end).
- **Memory** is a `MemContext`: a map from address expression to value expression, filled by STM. A load
  first looks for an earlier write to the same address, otherwise it returns `mem(addr)`, meaning "the
  memory content when the gadget starts". There is no aliasing analysis between different addresses.
  **The map is keyed by expression pointer, not by value**, so a load through a recomputed but equal
  address misses the write. This causes wrong results for gadgets that write to the stack and read it
  back ([KNOWN_ISSUES 1.1](KNOWN_ISSUES.md#1-chains-that-are-wrong-at-runtime)).
- **Registers used in an address** of any load or store are recorded as *dereferenced* (in terms of their
  initial values). Memory safety uses this list (§12).
- **Branches.** A BCC or JCC is only allowed when its condition is a constant node *as built*: there is no
  path forking. The condition isn't simplified first, so `1 & 0x3f` (the masked count of `shl eax, 1`)
  counts as non-constant. In practice shifts, rotates, `cmov`, `setcc`, `movsx`, `cdqe`, conditional jumps
  and string instructions without a preceding `cld`/`std` make the gadget fail here. A JCC must be taken:
  only unconditional transfers end a gadget.
- **Interrupts.** `int 0x80` ends the gadget as an INT80 gadget; any other interrupt fails. `syscall` (x64)
  and `sysenter` (x86) end it as a SYSCALL gadget.
- **Stack pointer tracking.** After **every** IR instruction, the stack pointer is simplified and must have
  the form `sp0`, `sp0 + k` or `sp0 − k`, with `k` a multiple of the word size. Otherwise the gadget is
  dropped (`leave`, `pop esp`, `xchg esp, eax`, `add esp, 3`, `push word`). The largest increment seen is
  kept as `max_sp_inc`.

The output is a `Semantics` object (final register expressions plus memory writes), simplified with the
default rule set before classification.

## 7. Expressions and simplification

**Expressions** (`libropium/include/expression.hpp`) are immutable-looking trees shared through
`shared_ptr` (`Expr`).

- **Node types:** CST, VAR, MEM, UNOP, BINOP, EXTRACT, CONCAT, BISZ, UNKNOWN.
- **Operators:** ADD, MUL, MULH, SMULL, SMULH, DIV, SDIV, NEG, AND, OR, XOR, SHL, SHR, MOD, SMOD, NOT.
  There is no SUB: `a − b` is `a + (−b)`.
- **Canonicalisation** happens when a node is built (`expr_canonize`). Associative and commutative
  operations are flattened, sorted and re-nested to the left, with constants first: `rax + 1` becomes
  `(0x1 + rax)`. The classifier relies on this shape (`args[0]` is the constant).
- **Constants** are stored sign-extended to 64 bits (`cst_t` is `int64_t`); operations truncate to their
  bit size.
- **Equality is a hash comparison** (Murmur3, 32 bits). Collisions are ignored by design.

**Simplification** (`libropium/symbolic/simplification.cpp`) runs a list of rewrite rules on a node, then
on its arguments, and repeats while the top level changes. The rules, in order:

1. constant folding;
2. neutral elements (`x + 0`);
3. absorbing elements (`x & 0`);
4. `x + −x`;
5. involutions (`−−x`, `~~x`);
6. EXTRACT/CONCAT patterns;
7. basic transforms (`x << c` → `x * 2^c`, `x >> c` → `x / 2^c`, `−x` → `−1 * x`, ...);
8. logical identities;
9. CONCAT patterns;
10. arithmetic factorisation;
11. generic factorisation.

Results are memoised on the nodes. It is not a complete normal form: for instance `8 + (8 + esp)` can
remain `((0x8 + 0x8) + esp)`.

**Concretization** evaluates an expression for given variable values, using a `VarContext`. The compiler
uses it to compute dependent constants such as "offset = other offset − 4". Details:

- Variable names are interned into a process-wide slot table, and a `VarContext` is an array indexed by
  slot.
- Every distinct content state of a context has a globally unique id, and each expression node caches
  its last concrete value with the id it was computed for. A cache hit therefore means "same variable
  values".
- Setting a variable to the value it already has keeps the id, so the caches stay valid.

## 8. Gadget acceptance and classification

`GadgetDB::analyse_raw_gadgets()` and `GadgetDB::add()` (`libropium/database/database.cpp`).

**Deduplication.** Accepted gadgets are remembered by their bytes: the same bytes at another address only
add that address to the existing gadget. When a chain uses the gadget, the first address without bad bytes
is chosen.

**Acceptance.** After lifting and symbolic execution:

1. every intermediate stack pointer value is known (§6), and `sp_inc` (the final increment) is a multiple
   of the word size;
2. the gadget ends with a SYSCALL or INT80, or the final PC has one of these shapes:

| Final PC | Branch type | Examples |
|---|---|---|
| a register `r` | **JMP**, `jmp_reg = r` | `jmp eax`, `call eax` (`sp_inc` = −4), `push eax; ret` |
| `mem(sp0 + c)` with `c + word == sp_inc` | **RET** | `ret`, `pop eax; ret` |
| anything else | rejected | `ret 8` (PC isn't the last slot read), `jmp [eax]`, direct jumps |

Negative `sp_inc` is allowed (needed by `call reg`). Note that the RET rule doesn't require `c ≥ 0`, see
[KNOWN_ISSUES 1.2](KNOWN_ISSUES.md#1-chains-that-are-wrong-at-runtime).

**Per-gadget data** (`Gadget`, `libropium/include/ropchain.hpp`):

- `addresses`;
- `sp_inc`, `max_sp_inc`, `branch_type`, `jmp_reg`;
- `modified_regs` (final expression ≠ initial variable; flags count);
- `dereferenced_regs`;
- `nb_instr` and `nb_instr_ir`, which define "shorter";
- `asm_str`, used in dumps.

**Classification.** Each final register expression and each memory write is matched against simple shapes,
and the gadget is filed under the key of every match. A gadget usually lands in several tables. The stack
pointer, PC and flag registers are classified like any other register.

| Table | Shape | Key | Examples |
|---|---|---|---|
| `mov_cst` | `reg = cst` | `(reg, cst)` | `mov eax, 3`; `xor eax, eax` (`eax = 0`, also `zf = 1`, ...) |
| `mov_reg` | `reg = src` | `(reg, src)` | `mov eax, ebx`, `xchg eax, edx` (two entries) |
| `amov_cst` | `reg = src OP cst` | `(reg, src, op, cst)` | `add eax, 4`; every `mov_reg` gadget also appears as `(reg, src, ADD, 0)`; every RET gadget is `(esp, esp, ADD, sp_inc)` |
| `amov_reg` | `reg = src1 OP src2` | `(reg, src1, op, src2)` | `add eax, ebx` (both operand orders for symmetric ops) |
| `load` | `reg = mem(src + off)` | `(reg, src, off)` | `mov eax, [ebx + 8]`; **`pop eax` is `load(eax, esp, 0)`**; the return address of a RET gadget is `load(eip, esp, sp_inc − 4)` |
| `aload` | `reg = reg OP mem(src + off)` | `(reg, op, src, off)` | `add eax, [ebx]` |
| `store` | `mem(dst + off) = src` | `(dst, off, src)` | `mov [eax + 8], ebx`; `push eax` is `store(esp, −4, eax)` |
| `astore` | `mem(dst + off) = mem(dst + off) OP src` | `(dst, off, op, src)` | `add [eax], ebx` |
| `jmp` | `pc = reg` | `reg` | filled but not queried by the compiler (JMP gadgets are reached through the other tables plus the branch type) |
| `syscall` / `int80` | ends in `syscall`/`sysenter` / `int 0x80` | `0` | |

There is no "pop" table: setting a register to a constant goes through the `mov_cst_pop` rewrite rule
(§11.5), which looks for a `load` from the stack pointer. Subtractions are canonicalised as
`(−1 * b) + a`, which matches no table.

**Order inside a key.** Gadgets are sorted by `(nb_instr, nb_instr_ir)`, shortest first. Among equal
sizes, a newly added gadget goes first.

## 9. Database queries

Each table is a `BaseDB<K>` (`libropium/include/database.hpp`): an `unordered_map` from key tuple to a
sorted gadget list.

| Query | Use | Behaviour |
|---|---|---|
| `get(key)` / `GadgetDB::get_mov_reg(...)`, ... | All parameters of a node are known | Exact lookup. A miss returns a shared empty list and **doesn't insert the key**. |
| `get_possible(key, is_free)` / `GadgetDB::get_possible_*(...)` | A node has free parameters | Scans all keys and keeps those whose non-free fields match. Results are ordered by the size of each key's best gadget. Ties come out in reverse hash-map iteration order. |
| `get_possible_cached(...)` | Used by the `GadgetDB::get_possible_*` wrappers | Same result, shared (`shared_ptr<const PossibleGadgets>`) and cached per query. A query is the free-field mask plus the values of the other fields. The cache is emptied by `add()` and `clear()`, and when it reaches 4096 entries. |
| `has_possible(key, is_free, branch)` | Early-fail check before a search | Is there a matching key with a gadget of the given branch type? Stops at the first match, allocates nothing. |

The cache is only correct because **a search never changes the tables**: `get()` must not insert on a miss,
and `add()`/`clear()` are only called while loading. A rehash would reorder the map and therefore the order
of ties in `get_possible` results, which decides which chain is found first.

## 10. The query language

`ROPCompiler::parse()` splits the program on newlines (blank lines are skipped) and parses each line into
an `ILInstruction` (`libropium/compiler/il.cpp`). A line is tried against each form in turn, and the first
that consumes the whole line wins.

| Form | IL type | Example |
|---|---|---|
| `reg = cst` | MOV_CST | `eax = 0x42`, `eax = -1` |
| `reg = reg` | MOV_REG | `eax = ebx` |
| `reg = reg OP cst` | AMOV_CST | `eax = ebx ^ 3`, `eax = ebx + -3` |
| `reg = reg OP reg` | AMOV_REG | `eax = ebx & ecx` |
| `reg = [reg ± cst]` | LOAD | `eax = [ebx + 16]`, `eax = [ebx]` |
| `reg = [cst]` | LOAD_CST | `eax = [0x12345678]` |
| `reg OP= [reg ± cst]` | ALOAD | `eax += [ebx + 16]` |
| `reg OP= [cst]` | ALOAD_CST | `eax ^= [0x1000]` |
| `[reg ± cst] = reg` | STORE | `[eax - 8] = ebx` |
| `[cst] = reg` | CST_STORE | `[0x1000] = ebx` |
| `[reg ± cst] OP= reg` | ASTORE | `[eax + 4] += ebx` |
| `[cst] OP= reg` | CST_ASTORE | `[0x1000] ^= ebx` |
| `[reg ± cst] = cst` | STORE_CST | `[eax + 4] = 0x42` |
| `[cst] = cst` | CST_STORE_CST | `[0x1000] = 0x42` |
| `[reg ± cst] OP= cst` | ASTORE_CST | `[eax + 4] += 0x42` |
| `[cst] OP= cst` | CST_ASTORE_CST | `[0x1000] \|= 0x42` |
| `[cst] = 'string'` | CST_STORE_STRING | `[0x1000] = '/bin/sh\x00'` |
| `cst(args)` | FUNCTION | `0x08041234(1, 2, eax)` (needs an ABI) |
| `sys_<num>(args)` / `sys_<name>(args)` | SYSCALL | `sys_0xb(0x1234, 0, 0)`, `sys_execve(0x1234, 0, 0)` (needs `OS.LINUX`) |
| `syscall` | SINGLE_SYSCALL | `syscall` |

**Lexical rules.**

- Registers are lower-case names valid for the architecture (x64 has no 32-bit sub-registers in queries).
- Constants are decimal or `0x` hex, optionally negative.
- Binary operators: `+ * / % & | ^ << >>`. There is no binary `-`: write `+ -3`.
- `OP=` exists only with a memory operand.
- Strings use `'` or `"`, with the escapes `\\`, `\'`/`\"` and `\xHH`, and can only be stored at a
  constant address.
- Function arguments are constants or registers.
- A malformed line raises `il_exception` (Python `ValueError: Invalid query: ...`). Semantic errors (no
  ABI, unknown syscall, too many arguments) raise a `RuntimeError` in Python.

## 11. The compiler

### 11.1 Pipeline

`ROPCompiler::compile()` (`libropium/compiler/compiler.cpp`):

1. Opens a `SearchDeadlineScope` for `timeout_ms` (one deadline for the whole call).
2. `_compile()`:
   - parses the program;
   - prepares the constraint (the stack pointer is always a safe pointer);
   - looks at the **first** instruction only. A syscall, or a function call with an x64 ABI, goes to
     `process_complex()`. Everything else goes to `process_simple()`.
3. `process_simple()`:
   - `preprocess()` splits string stores into one word store per machine word;
   - each instruction is compiled by its own `CompilerTask` (one strategy graph, one try budget);
   - the chains are concatenated in order. Instructions don't know about each other, so a later line
     can clobber an earlier result.
4. `last_compile_timed_out` = no chain **and** a check saw the deadline.

### 11.2 Strategy graphs

A `StrategyGraph` (`libropium/include/strategy.hpp`) is a list of `Node`s.

**A node** is an abstract gadget slot with:

- a `GadgetType` (MOV_CST, MOV_REG, AMOV_CST, AMOV_REG, LOAD, ALOAD, STORE, ASTORE, SYSCALL, INT80) and
  one `Param` per field of that type's database key, in the same order.
- four generic parameters, filled in when a gadget is assigned: `gadget_addr`, `gadget_sp_inc`,
  `gadget_jmp_reg` and `gadget_sp_delta` (= `max_sp_inc − sp_inc`). Other parameters can depend on them.
- a required `branch_type` (RET, JMP or ANY).
- **special paddings**: stack words written after the gadget at a given offset, e.g. the constant
  popped by `pop`, function arguments, or the address of an *indirect* gadget.
- **strategy constraints** (checked once the parameters are resolved) and **assigned-gadget constraints**
  (checked once a gadget is chosen). Every node checks the branch type.
- **valid pointers**: parameters that the query guarantees to be valid addresses (the base register of a
  load or store). Memory safety uses them.
- flags: `is_indirect` (the gadget isn't emitted as a chain item, only its address appears as data),
  `is_disabled` (replaced by a rule, but may still hold constants others depend on), and
  `mandatory_following_node`.

**A parameter** is fixed (given by the query), free (chosen by the search), or dependent: a register copied
from another node's parameter, or a constant computed by an expression over other constants' names. It is
flagged as a **data link** when it carries a value that must not be clobbered between its producer and its
consumer.

**Edges:**

- *strategy edges*: A before B, i.e. execution order;
- *param edges*: A's parameters depend on B;
- *interference edges*: temporary ordering choices made by scheduling.

### 11.3 Initial graphs

`il_to_strategy()` builds one graph per IL instruction:

| IL | Graph |
|---|---|
| MOV_CST, MOV_REG, AMOV_CST, AMOV_REG, LOAD, ALOAD, STORE, ASTORE | one node of the same type |
| LOAD_CST / ALOAD_CST | `MOV_CST X ← (C − off)`, then `LOAD dst ← [X + off]` (X and off free) |
| CST_STORE / CST_ASTORE | `MOV_CST X ← (C − off)`, then `STORE [X + off] ← src` |
| STORE_CST / ASTORE_CST | `MOV_CST R ← cst`, then `STORE [addr + off] ← R` |
| CST_STORE_CST / CST_ASTORE_CST | two MOV_CST nodes (address and value), then a STORE |
| FUNCTION (X86_CDECL / X86_STDCALL) | a call node `eip ← func` whose paddings are the return address and the arguments, plus an indirect "return" node that skips the arguments (cdecl) or not (stdcall) |
| SINGLE_SYSCALL | one SYSCALL node |

### 11.4 The search loop

`CompilerTask::compile()`:

```
while tries remain and the queue isn't empty and no chain:
    stop if Ctrl+C was pressed or the deadline is reached
    graph = queue.pop()
    if graph.select_gadgets(db, constraint): chain = graph.get_ropchain()
    else: apply_rules_to_graph(graph)          # queue the rewritten alternatives
```

The **queue** (`StrategyQueue`) pops the graph with the fewest enabled nodes first, and the most recently
added one among graphs of equal size. When it already holds at least as many graphs as there are tries
left, a new graph is rejected unless it is smaller than the largest queued graph. **One try is one popped
graph** (`max_tries`, default 3000, per task).

### 11.5 Rewrite rules

`apply_rules_to_graph()` tries every rule on every enabled, non-indirect node, in node order. The rule
order is fixed: transitivity, mov_cst_pop, adjust_jmp, adjust_load, src_transitivity, adjust_store. Each
success queues one new graph (`libropium/compiler/strategy_rules.cpp`).

| Rule | Applies to | Rewrite |
|---|---|---|
| `generic_transitivity` | nodes writing a register | `dst ← x` becomes `R ← x; dst ← R` with a free register `R` |
| `mov_cst_pop` | MOV_CST (not JMP) | `dst ← C` becomes `dst ← [sp + off]` (free `off`, 0 ≤ off < 240) plus a padding `C` at `off`, where `off` must lie inside the gadget's stack frame (not on the return slot unless `dst` is PC) |
| `generic_adjust_jmp` | RET/ANY nodes | the node may end with `jmp J` instead of `ret`. A new node first sets `J` to the address of an indirect "return" gadget (`LOAD pc ← [sp + sp_delta]`) that continues the chain. The jump register must not be an operand of the node. |
| `adjust_load` | LOAD/ALOAD whose base isn't sp | `dst ← [A + off]` becomes `X ← A + (off − off2); dst ← [X + off2]` |
| `generic_src_transitivity` | STORE/ASTORE | `[A + off] ← S` becomes `R ← S; [A + off] ← R` |
| `adjust_store` | STORE/ASTORE whose base isn't sp | like `adjust_load`, for the address register |

### 11.6 Gadget selection

`StrategyGraph::select_gadgets()` is a backtracking search over the nodes in parameter-dependency order
(`dfs_params`).

At the **root** call:

1. **Early fail**: for every enabled node, ask `has_possible_*` whether any gadget can match its *constant*
   parameters and branch type (free and dependent parameters match anything). If one can't, the graph
   fails at once. This is sound, and still uses one try and applies the rules.
2. **Save the node state** (parameter values and assigned gadgets). If the search fails, restore it, so
   the rules applied next never see values left by the last candidate tried.

For **each node**:

- **Disabled node**: only resolve its dependent parameters.
- **Node with free parameters**: enumerate `get_possible_*` entries. For each entry:
  - write the free values and resolve dependent parameters;
  - check the strategy constraints and that the special paddings have no bad bytes;
  - for each gadget of that key: assign it (first address without bad bytes), check the assigned-gadget
    constraints, keep_regs and memory safety, then recurse into the next node.
- **Node without free parameters**: same, over the exact-lookup list.

**At the leaf**, `schedule_gadgets()` must order the selection (§11.7). The first full success wins.

The search checks for Ctrl+C and polls the deadline at every call and in every candidate loop.

### 11.7 Scheduling

Scheduling makes sure no gadget clobbers a data-link register between its producer and consumer.

1. `compute_interference_points()` lists, for every data-link parameter, the other nodes whose gadget
   modifies that register. Each such node must run before both endpoints or after both:
   - an initial input must not be clobbered before it is read;
   - a final output must not be clobbered after it is written.
2. `_do_scheduling()` backtracks over before/after choices as interference edges. It polls the deadline
   at every step.
3. `compute_dfs_scheduling()` checks that the result has no cycle. Its reversed post-order is the
   execution order, with each mandatory following node placed right after its owner.

### 11.8 Chain emission

`get_ropchain()` walks the execution order and skips indirect nodes. For each node it emits:

- the gadget address;
- `sp_inc / word` stack words, minus one for a RET gadget (the next chain item is its return address),
  extended so the highest special padding fits.

A stack word holds a special padding if one sits at that offset; a padding whose value is a gadget
address is emitted as a *gadget address* item, with that gadget's text. Every other word gets the default
padding: the highest byte value that isn't a bad byte, repeated (`0xffffffff` with no bad bytes).

### 11.9 Function calls and syscalls

| Query | ABI / OS | How |
|---|---|---|
| `func(args)` | `X86_CDECL`, `X86_STDCALL` | One graph (§11.3); only constant arguments. |
| `func(args)` | `X64_SYSTEM_V` | `process_complex`: set RDI, RSI, RDX, RCX, R8, R9 with `_set_multiple_registers()`, then compile a call graph that keeps those registers (stack arguments as paddings). |
| `func(args)` | `X64_MS` | Same, with RDX, RCX, R8, R9 (see [KNOWN_ISSUES 1.7](KNOWN_ISSUES.md#1-chains-that-are-wrong-at-runtime)). |
| `sys_*(args)` | `OS.LINUX`, x86 | Arguments in EBX, ECX, EDX, ESI, EDI, EBP, number in EAX, then a nested `compile("syscall")` that keeps the argument registers. |
| `sys_*(args)` | `OS.LINUX`, x64 | Arguments in RDI, RSI, RDX, R10, R8, R9, number in RAX, then the nested `syscall`. |

`_set_multiple_registers()` tries the orders of the register assignments given by `std::next_permutation`.
Each step is its own task that keeps the registers already set. Failed orders are recorded to skip similar
ones. The cost grows as n! with the number of registers.

### 11.10 Bounded search

| Limit | Scope | Effect |
|---|---|---|
| `max_tries` (`rop.max_tries`, default 3000) | per `CompilerTask` (one per program line, per register-setting step, per call/syscall graph) | number of graphs popped; also caps the queue |
| `timeout_ms` (`rop.timeout`, seconds, `None` = no limit) | the whole `compile()` call | process-wide deadline (`set_search_deadline()`): read on every task iteration and before each permutation, and polled (clock read every 256 polls) in the DFS and scheduling. Once seen it stays reached, so every frame unwinds. |
| Ctrl+C | the current task | a C signal handler sets a flag that the search checks; the task returns no chain, and the next task (if any) continues |

A deadline never changes the search order: the result is either the unbounded result or `None` with
`timed_out` set. `None` with `timed_out == False` means the try budget ran out or every graph failed, which
is not a proof that no chain exists.

## 12. Constraints

`Constraint` (`libropium/include/constraint.hpp`) holds:

- **`BadBytes`**: a 256-bit set.
  - A gadget is usable if one of its addresses has no bad byte (`assign_gadget` picks it).
  - Special paddings (constants, offsets, addresses written into the chain) must have no bad bytes.
  - The default padding avoids them.
- **`KeepRegs`**: a gadget is rejected if it modifies a kept register (`modified_regs`). The compiler adds
  internal kept registers when setting several registers or calling functions.
- **`MemSafety`** (`rop.safe_mem`, on by default): a gadget is rejected if it reads or writes memory through
  a register that is neither the stack pointer nor a *valid pointer* of its node (e.g. the base register of
  the queried load or store). There is no value tracking: it is a rule about which registers' roles make
  them safe to dereference.

During the search the check is `check_except_bad_bytes()` (keep_regs + memory safety), because
`assign_gadget` already chose an address without bad bytes.

## 13. ROP chains and dump formats

A `ROPChain` (`libropium/include/ropchain.hpp`) is a list of items:

- a gadget (address + gadget);
- a padding (a value);
- a gadget address used as data (value + the gadget's text).

`chain.dump(fmt, tab, color)` produces:

| Format | Output |
|---|---|
| `'pretty'` (default) | one line per item: `0x...` and the gadget text in parentheses for gadgets and gadget addresses |
| `'raw'` | `bytes`: little-endian words, ready to append to a payload |
| `'python'` | a `struct.pack` script, Python-2 style (doesn't run as-is on Python 3) |

Colors (ANSI codes) are on unless `color` is false; `str(chain)` always uses them.

## 14. Python bindings and CLI

- **Python** (`bindings/`):
  - The module exposes `ROPium(arch)` (a factory), `ARCH`, `ABI`, `OS`, and `X86`/`X64` register
    constants.
  - A `ROPium` object owns its gadget database, its `ROPCompiler` and a persistent `Constraint`, so
    `bad_bytes`, `keep_regs` and `safe_mem` persist between `compile()` calls.
  - Chains borrow the gadgets of their `ROPium` object, so keep it alive.
  - `compile()` holds the GIL. The deadline, the Ctrl+C handler and the dump colors are process-wide.
- **CLI** (`cli-tool/ropium`):
  - It keeps its settings (bad bytes, keep regs, safe mem, ABI, OS, timeout, max tries) in module
    globals and applies them to the `ROPium` object before every `find`.
  - It uses prompt_toolkit for the prompt and history.

## 15. Rules for changing the search

The corpus fixture (`tests/perf_baseline.json`) requires byte-identical chains. A change that keeps the
following true keeps results identical:

1. **The database is immutable during a search.** No inserts on lookup misses; `add()`/`clear()` only while
   loading; the `get_possible` cache depends on it.
2. **Keep the `get_possible` order**, including ties (reverse hash-map iteration order) and the gadget order
   inside keys: it decides which chain is found first.
3. **A failed `select_gadgets()` leaves the graph unchanged**: rules read parameter values
   (`adjust_load`/`adjust_store` compare a register value to `sp`, `mov_cst_pop` copies a parameter).
4. **Early fails must be sound**: only constant parameters and the branch type may be compared, and a
   failed graph must still use one try and get the rules applied. Dropping graphs before they are queued
   loses rule-derived strategies and is wrong.
5. **Keep the queue order** (smallest first, LIFO among equal sizes, the reject rule computed with the
   remaining budget), the node order and the rule order.
6. **The deadline may stop the search but never reorder it.**

See [DEVELOPMENT.md](DEVELOPMENT.md) for the tools that check these rules.

## 16. Performance notes

Where the time goes:

- **Failed searches** dominate. A query with no solution makes the compiler try up to `max_tries` graphs,
  each with a full backtracking search.
- **On large gadget sets**, the DFS enumerates many `get_possible` candidates per node, so per-candidate
  bookkeeping (parameter resolution, constraint checks) dominates.
- **On small gadget sets**, copying strategy graphs when applying rules dominates.

What makes it fast today:

- integer-slot `VarContext`s with globally unique state ids;
- a bucketed queue with O(log n) push and pop;
- exception-free address selection and a bad-byte bitmap;
- the early fail, which turns a doomed search from minutes into milliseconds;
- the `get_possible` cache.

Practical advice:

- Use `rop.timeout` to bound latency. Unsatisfiable queries usually fail in well under a second thanks to
  the early fail, but some still enumerate for a long time.
- Load only the gadgets you need: search time grows with the number of candidates per key.
