# ROPium Internals — How It Works

This document explains how ROPium operates end-to-end: how gadgets get into the tool,
how they are analyzed, and how ROP chains are compiled from semantic queries.
It also documents the **rp++** integration in detail (see the [rp++ section](#rp-integration)).

---

## 1. Overview

ROPium is a **ROP-chain compiler**. Instead of making you hand-assemble gadget sequences,
you describe *what you want the chain to achieve* with a small semantic language
(e.g. `eax = 0x1234`, `[eax-8] = ebx`, `sys_execve(0x1234, 0, 0)`) and ROPium
searches its gadget database for a sequence of gadgets that satisfies the query.

```
                ┌─────────────────────────────────────────────────────┐
 binary ──────► │  gadget extraction (ROPgadget or rp++ output file)  │
 rp++ file ───► │                                                     │
                └───────────────────────┬─────────────────────────────┘
                                        │  raw gadgets: "addr$hexbytes"
                                        ▼
                ┌─────────────────────────────────────────────────────┐
                │  analysis: disasm (Capstone) → IR → symbolic engine  │
                │  → simplified semantics → typed gadget database     │
                └───────────────────────┬─────────────────────────────┘
                                        │
                                        ▼
                ┌─────────────────────────────────────────────────────┐
 query ───────► │  compiler: IL parse → StrategyGraph → gadget        │ ───► ROPChain
 constraints ► │  selection + strategy rules (search)                 │      (pretty /
                └─────────────────────────────────────────────────────┘       python / raw)
```

## 2. Components

| Component | Location | Role |
|---|---|---|
| Core C++ library | `libropium/` | Disassembly, IR, symbolic execution, gadget DB, compiler |
| Python bindings | `bindings/` | CPython extension exposing `ROPium`, `ROPChain`, `ARCH`, `ABI`, `OS`, `X86`, `X64` |
| CLI tool | `cli-tool/ropium` | Interactive prompt (`load`, `load_rp`, `find`, `badbytes`, ...) |
| Example script | `RopChainer.py` | Minimal Python API usage example |
| Sample binaries | `samples/binaries/` | Windows PE targets (`efssetup.exe`, `QuoteDB.exe`, `vulnserver.exe`) |
| Sample gadget dumps | `samples/gadgets/` | Pre-generated rp++ outputs for the sample binaries |
| Bundled tools | `samples/tools/` | `rp-win_x86_v6.exe` (rp++ v2.1.5 x86 Windows build), `ROPgadget` (aarch64 build) |

Build & install: `make` (builds `bin/libropium.so`, `bin/tests`, and the Python module
`bin/ropium.so`), then `make install` (installs the shared lib, headers, Python module
into the user site-packages, and the `ropium` CLI into `$PREFIX/bin`).

## 3. Gadget ingestion — the two `load` paths

### 3.1 Internal raw-gadget format

Everything the analyzer consumes is a list of `RawGadget { addr, raw bytes }`.
The interchange format written to temp files is one gadget per line:

```
<address-hex>$<hex-bytes>
```

e.g. `0x12345678$89D8C3` (see `tests/ressources/gadgets.txt`).
Parsing lives in `raw_gadgets_from_file()` (`libropium/utils/utils.cpp`).

### 3.2 `load <binary>` — via ROPgadget

`ROPium.load(file)` (Python) / `load -a ARCH file` (CLI) does **not** implement its own
ELF/PE gadget scanner. It shells out to [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
(`ropgadget_to_file()` in `libropium/utils/utils.cpp`):

```
ROPgadget --binary <file> --dump --all --depth 15 > tmp
```

It then parses ROPgadget's `0xADDR : asm // hexbytes` lines into the raw format.
**Requirement:** the `ROPgadget` command must be on `$PATH` (`pip install ROPgadget`).

### 3.3 `load_rp <file>` — via rp++ output

`ROPium.load_rp(file)` (Python) / `load_rp file` (CLI) ingests a **text file produced by
rp++** (`rp_gadgets_to_file()` in `libropium/utils/utils.cpp`). This is the integration
used by the files in `samples/gadgets/`. Details in the [rp++ section](#rp-integration).

Both paths end in `GadgetDB::analyse_raw_gadgets()`.

## 4. Gadget analysis pipeline

For every raw gadget (`libropium/database/database.cpp`):

1. **Disassemble** with Capstone into an `IRBlock` (`libropium/arch/disassembler.cpp`,
   `archX86.cpp`). Gadgets that fail to lift are dropped.
2. **Symbolic execution** (`libropium/symbolic/`): the `SymbolicEngine` walks the IR and
   produces a `Semantics` object: one symbolic `Expr` per register (`IRContext`) plus a
   map of memory writes (`MemContext`). Expressions support CST/VAR/MEM/UNOP/BINOP/
   EXTRACT/CONCAT/BISZ (`libropium/include/expression.hpp`).
3. **Simplification** (`libropium/symbolic/simplification.cpp`) canonicalizes expressions.
4. **Sanity checks**: the gadget must have a *known stack-pointer increment* that is a
   multiple of the architecture word size, and must end in a recognized branch
   (`RET`, `JMP reg`, `SYSCALL`, or `INT80`). Gadgets that don't qualify are dropped.
5. **Classification**: based on the final register/memory expressions, the gadget is
   inserted into typed hash-map databases keyed by its semantic tuple
   (`GadgetDB` in `libropium/include/database.hpp`):

   | DB | Meaning | Example gadget |
   |---|---|---|
   | `mov_cst` | `reg ← cst` | `pop eax; ret` |
   | `mov_reg` | `reg ← reg` | `mov eax, ebx; ret` |
   | `amov_cst` | `reg ← reg OP cst` | `add eax, 4; ret` |
   | `amov_reg` | `reg ← reg OP reg` | `add eax, ebx; ret` |
   | `load` / `aload` | `reg ← mem(reg+off)` (+ OP=) | `mov eax, [ebx+8]; ret` |
   | `store` / `astore` | `mem(reg+off) ← reg` (+ OP=) | `mov [eax+8], ebx; ret` |
   | `jmp` | `PC ← reg` | `jmp eax` |
   | `syscall` / `int80` | ends in syscall / int 0x80 | `syscall` |

   Identical gadgets (same bytes) are deduplicated; only new addresses are appended.
   Gadgets are kept sorted shortest-first so chains prefer compact gadgets.

## 5. The query language (IL)

Queries are parsed by `ROPCompiler::parse()` into `ILInstruction`s
(`libropium/compiler/il.cpp`). One instruction per line; supported forms:

```text
eax = 0x42                  # reg ← constant
eax = ebx                   # reg ← reg
eax = ebx ^ 3               # reg ← reg OP cst
eax = ebx & ecx             # reg ← reg OP reg
eax = [ebx + 16]            # reg ← mem(reg + off)
eax = [0x12345678]          # reg ← mem(cst)
eax += [ebx + 16]           # reg OP= mem(reg + off)
eax *= 2                    # reg OP= cst
[eax - 8] = ebx             # mem(reg + off) ← reg
[0x12345678] = 0x42         # mem(cst) ← cst
[0x12345678] = '/bin/sh\x00'# mem(cst) ← string
0x08040120()                # call function at address (ABI required)
0x08040120(1, 2, 3)         # call with constant args
sys_execve(0x1234, 0, 0)    # Linux syscall by name (OS required)
sys_0xb(0x1234, 0, 0)       # Linux syscall by number
syscall                     # bare syscall gadget
```

Operators: `+ - * / % & | ^ << >>` (and compound `+= -= *= ...`).

## 6. Compilation — StrategyGraphs and strategy rules

`ROPCompiler::compile()` (`libropium/compiler/compiler.cpp`):

1. **Preprocess** complex instructions into simpler IL (e.g. `mem(cst) ← cst`
   becomes "set an address register" + "store").
2. **IL → StrategyGraph**: each instruction becomes a graph whose *nodes* are gadget
   slots (typed like the DB) with fixed/free/dependent *params*, and whose *edges*
   encode data and ordering dependencies (`libropium/compiler/strategy_graph.cpp`).
   Function calls are expanded per-ABI (`X86_CDECL`, `X86_STDCALL`, `X64_SYSTEM_V`,
   `X64_MS`); syscalls per-OS/arch (Linux x86 `int 0x80`/sysenter, Linux x64 `syscall`).
3. **Search** (`CompilerTask::compile`): repeatedly take the most promising pending
   graph and try `select_gadgets()` — a backtracking assignment of DB gadgets to nodes,
   honoring constraints. On success, emit the `ROPChain` (gadget addresses + stack
   paddings computed from each gadget's `sp_inc`).
4. **Strategy rules**: on failure, transform the graph into new candidate graphs —
   generic transitivity (`mov` through a scratch register), `mov cst` pop adjustment,
   jmp adjustment, load/store offset adjustment, source-register transitivity
   (`libropium/compiler/strategy_rules.cpp`) — and re-queue them (bounded to 3000 tries;
   Ctrl+C aborts cleanly).
5. **Multi-register queries** try permutations of assignment order, recording failed
   prefixes to prune the search.

### Constraints (applied during gadget selection)

| Constraint | Python attr | CLI | Effect |
|---|---|---|---|
| Bad bytes | `rop.bad_bytes = [0x0a, 0x00]` | `badbytes set 0 0xa` | Gadget addresses/paddings may not contain these bytes |
| Keep regs | `rop.keep_regs = ["esi"]` | `keepregs set esi` | Gadgets clobbering these registers are rejected |
| Safe memory | `rop.safe_mem = True` | `safemem set/unset` | Reject gadgets dereferencing registers with unknown values |
| ABI | `rop.abi = ABI.X86_STDCALL` | `abi set X86_STDCALL` | Calling convention for `0xaddr(args)` queries |
| OS | `rop.os = OS.LINUX` | `os set LINUX` | Syscall tables for `sys_*` queries |

### ROPChain output

`chain.dump(fmt)` supports:

- `'pretty'` — annotated address list (default `print(chain)`)
- `'python'` — ready-to-paste `struct.pack` snippet
- `'raw'` — raw little-endian bytes (`bytes`) for direct payload use

Chains support `+` concatenation in Python.

## 7. rp++ integration

ROPium can ingest gadget listings produced by
[rp++](https://github.com/0vercl0k/rp) (a fast ROP gadget finder for PE/ELF/Mach-O).
This is what the files under `samples/` demonstrate.

### 7.1 What's in `samples/`

- `samples/tools/rp-win_x86_v6.exe` — bundled rp++ **v2.1.5 x86 Windows** build
  (run it with Wine on Linux, or use a native rp++ build).
- `samples/binaries/*.exe` — sample PE32 targets.
- `samples/gadgets/efssetup.txt`, `vulnserver_3.txt`, `mp3_conf.txt` — rp++ dumps of the
  sample binaries, ready to be fed to `load_rp`.

### 7.2 Generating a gadget file with rp++

rp++ finds gadgets with `-f/--file` and `-r/--rop <max-instructions>`; **`--print-bytes`
is required** because ROPium's parser needs the raw hex bytes of each gadget:

```bash
# Windows (or Wine on Linux):
rp-win_x86_v6.exe -f efssetup.exe -r 10 --print-bytes > efssetup.txt

# Recommended: deduplicate gadgets
rp-win_x86_v6.exe -f efssetup.exe -r 10 --print-bytes --unique > efssetup.txt
```

Useful rp++ flags (from the bundled binary's usage):

| Flag | Meaning |
|---|---|
| `-f, --file <path>` | binary to analyze |
| `-r, --rop <n>` | max number of instructions per gadget (default 5) |
| `--unique` | keep only unique gadgets (smaller files, faster load) |
| `--print-bytes` | **required** — emit raw bytes so ROPium can re-analyze |
| `--raw` | analyze a raw file |
| `--va <base>` | override the image base address |
| `--allow-branches` | allow branch instructions inside gadgets |
| `--max-thread <n>` | cap the number of worker threads |
| `--bad-bytes` | filter gadgets containing given bytes |
| `--search-int` / `--search-hexa` | find pointers to values (not used by ROPium) |

### 7.3 rp++ output formats the parser understands

`rp_gadgets_to_file()` (`libropium/utils/utils.cpp`) is tolerant of both rp++ v2
listings and the older v6-style dumps:

```
0x00403e23 : aaa ; xor eax, eax ; jmp 0x403e30 // 37383941424344454633c0eb00
0x4236a3: aaa ; add [eax], eax ; pop edi ; pop esi ; ret ; \x37\x3e\x01\x00\x5f\x5e\xc3 (1 found)
```

The parser, per line:

1. converts UTF-16 → UTF-8 (rp++ Windows output),
2. strips `(N found)` suffixes and trailing whitespace,
3. splits on spaces; the **first token must start with `0x`** (the address) and the
   **last token is the raw byte string** — so lines must contain the bytes
   (`--print-bytes`), otherwise the line is skipped,
4. removes `\x` escapes from `\x37\x3e...`-style byte strings,
5. writes `address$hexbytes` lines consumed by the analyzer.

Header/footer lines (`Gadgets information`, `Unique gadgets found: N`, rp++ banners)
are ignored automatically because they don't match the `0x...` pattern.

### 7.4 Loading rp++ gadgets

CLI:

```
(ropium)> load_rp samples/gadgets/efssetup.txt
(ropium)> find eax = 0x1234
```

Python:

```python
from ropium import ROPium, ARCH

rop = ROPium(ARCH.X86)
rop.load_rp('samples/gadgets/efssetup.txt')   # rp++ output file
chain = rop.compile('eax = 0x1234')
print(chain.dump('python'))
```

Notes:

- The architecture is chosen when the `ROPium` object is created (`ARCH.X86` for the
  32-bit sample binaries); `load_rp` assumes the dump matches that architecture.
- `load` (ROPgadget path) and `load_rp` (rp++ path) populate the same database, so you
  can mix gadget sources (e.g. binary + rp++ dump of a loaded DLL).
- rp++ is only used **offline** to produce the text file; ROPium re-disassembles and
  re-analyzes the raw bytes itself, so the chain quality depends on ROPium's own
  semantic analysis, not rp++'s.

## 8. CLI reference (`cli-tool/ropium`)

```
load [-a X86|X64] <file> [...]   load gadgets from a binary (uses ROPgadget)
load_rp <file> [-a X86|X64]      load gadgets from an rp++ output file
find <query>                      compile a semantic query into a ROP chain
badbytes set B.../reset           bytes forbidden in chain addresses/paddings
keepregs set R.../reset           registers that must not be clobbered
safemem set/unset                 forbid/allow dereferencing unknown registers
abi set X86_CDECL|X86_STDCALL|X64_SYSTEM_V|X64_MS
os set LINUX|WINDOWS
help [cmd] / exit
```

## 9. Testing

`make test` builds and runs `bin/tests` (`tests/test_all.cpp`), covering expressions,
simplification, IR, gadget analysis, the database, strategy graphs, the IL parser and
the compiler (including end-to-end chain finding against synthetic gadget sets).
Individual suites: `./bin/tests expr|simp|ir|gadgets|db|strategy|il|compiler`.
