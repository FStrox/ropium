

<p align="center" >
<img width=50% src="/ressources/ropium_logo.png"/><br /><br /><br />
</p>

# About
**ROPium** (ex-ROPGenerator) is a library/tool that makes ROP-exploits easy. It analyses the gadgets of a binary
and lets you find ROP-chains with semantic queries. ROPium supports the *X86* and *X64* architectures.

Key features:

   - **Effortless**: ROPium works out-of-the-box with a smooth Command Line Interface
   - **Python API**: It is easy to integrate ROPium in scripts thanks to its Python API
   - **Automatic chaining**: ROPium automatically combines gadgets to create complex ROP-chains
   - **Advanced features**: ROPium supports function calls for various ABIs, syscalls, string writes, constraints (bad bytes, registers to keep, memory safety)
   - **Bounded search**: impossible queries usually fail in well under a second, and a timeout bounds the rest
   - **Semantic queries**: ROPium queries are quick and convenient to write: ``eax = ebx + 8``, ``[edi + 0x20] = eax``, ``esi = [ebx + 16]``, ``0x08040212(1, 2, eax)``, ``[0xdeadbeef] = '/bin/sh\x00'``, ``sys_0xb(0x1234, 0, 0)``

# Content
- [About](#about)
- [Quick start](#quick-start)
- [Showcase](#showcase)
- [Installation](#installation)
- [Usage](#usage)
   - [CLI tool](#cli-tool)
   - [Python API](#python-api)
   - [Query language](#query-language)
   - [Constraints and search limits](#constraints-and-search-limits)
- [Gadget sources](#gadget-sources)
- [Docker](#docker)
- [How it works](#how-it-works)
- [Known limitations](#known-limitations)
- [Development](#development)
- [Contact](#contact)
- [Licence](#licence)
- [Special thanks](#special-thanks)

# Quick start

You can use ROPium straight from the source tree, without installing anything system-wide:

```bash
sudo apt install g++ make libcapstone-dev python3-dev python3-prompt-toolkit   # Debian/Ubuntu/Kali
make -j4                                    # builds bin/libropium.so, bin/tests and the Python module bin/ropium.so

python3 examples/showcase.py                # compile the showcase queries below
PYTHONPATH=bin python3 cli-tool/ropium      # start the interactive CLI
```

In the CLI, load one of the bundled gadget files and ask for a chain:

```
(ropium)> load_rp samples/gadgets/vulnserver_3.txt
(ropium)> find ebx = 0xdeadbeef

	0x00402673 (pop ebx; pop ebp; ret)
	0xdeadbeef
	0xffffffff
```

Or from Python:

```python
import sys; sys.path.insert(0, "bin")         # not needed once ROPium is installed
from ropium import ROPium, ARCH

rop = ROPium(ARCH.X86)
rop.load_rp("samples/gadgets/efssetup.txt")
chain = rop.compile("ecx = edx")
print(chain.dump())
```

<p align="center">
  <img src="/ressources/ropium.gif" width="800" align="middle">
</p>

# Showcase

Every chain below comes from the gadget files bundled in `samples/gadgets/` (32-bit Windows programs, so
`ARCH.X86`). `python3 examples/showcase.py` reproduces all of them. The chains are printed with
`chain.dump()`: one stack word per line, with the gadget's instructions in parentheses.

**Move a register through another one**: `ecx = edx` (efssetup). No gadget does `ecx <- edx`, so ROPium
routes the value through `eax`:

```
0x004027af (mov eax, edx; ret)
0x0040509e (mov ecx, eax; lea esi, [ebp - 0x48]; ret)
```

**Load a constant**: `ebx = 0xdeadbeef` (vulnserver_3). The constant is popped from the stack, and
`0xffffffff` fills the slot of the extra `pop ebp`:

```
0x00402673 (pop ebx; pop ebp; ret)
0xdeadbeef
0xffffffff
```

**Store a constant in memory**: `[ecx + 4] = 0x1234` (efssetup). `push ecx; pop edx` copies the address
into `edx` so that a `mov [edx + 4], ebx` gadget can do the store:

```
0x004012ad (pop ebx; ret)
0x00001234
0x004073f1 (push ecx; or al, 0x59; pop edx; ret)
0x00401d77 (mov dword ptr [edx + 4], ebx; pop edi; pop esi; pop ebx; ret)
0xffffffff
0xffffffff
0xffffffff
```

**Write a string**: `[0x0804a000] = '/bin/sh\x00'` (efssetup). Strings are written one machine word at a time:

```
0x00402aeb (pop edx; ret)
0x0804a000
0x00402b46 (pop eax; ret)
0x6e69622f
0x004030c6 (mov dword ptr [edx], eax; ret)
0x00402aeb (pop edx; ret)
0x0804a004
0x00402b46 (pop eax; ret)
0x0068732f
0x004030c6 (mov dword ptr [edx], eax; ret)
```

**Several instructions**: `"eax = 1\nebx = 2"` (efssetup). Each line is compiled in turn and the chains are
concatenated:

```
0x00402cc5 (mov eax, 1; ret)
0x004012ad (pop ebx; ret)
0x00000002
```

**Call a function**: `0x10001234(1, 2)` (efssetup). With `rop.abi = ABI.X86_CDECL` the caller cleans the
stack, so the function returns into a `pop; pop; ret` that skips both arguments:

```
0x00401178 (ret)
0x10001234
0x00404ce6 (pop esi; pop edi; ret)
0x00000001
0x00000002
```

With `rop.abi = ABI.X86_STDCALL` the function removes its own arguments, so it returns into a plain `ret`:

```
0x00401178 (ret)
0x10001234
0x00401178 (ret)
0x00000001
0x00000002
```

**Gadgets that end with a call**: `ebx = eax` (mp3_conf). The only `mov ebx, eax` gadget ends with
`call edi`, so ROPium first loads `edi` with the address of a `pop esi; ret` gadget (second line: it is data
popped into `edi`, shown with its instructions). When `call edi` runs, that gadget removes the return
address pushed by `call`, and the chain continues:

```
0x0040156f (pop edi; ret)
0x00401552 (pop esi; ret)
0x0041797d (mov ebx, eax; call edi)
```

**Constraints change the chain**: `ecx = edx` (efssetup) with `rop.bad_bytes = [0xaf]`. The first gadget's
address `0x004027af` now contains a bad byte, so ROPium picks another `mov eax, edx` gadget:

```
0x00403451 (mov eax, edx; ret)
0x0040509e (mov ecx, eax; lea esi, [ebp - 0x48]; ret)
```

**Impossible queries fail fast, long searches can be bounded** (efssetup):

```python
rop.compile("eax = ebx + ecx")   # None after ~0.4 s: these gadgets can't add two registers
rop.timeout = 2
rop.compile("eax = [ebx + 4]")   # None after 2 s, and rop.timed_out is True
```

# Installation

## Requirements

- `g++` and `make`
- [Capstone](https://www.capstone-engine.org/) with its headers (`libcapstone-dev`)
- Python 3 with its headers (`python3-dev`), for the Python module
- [prompt_toolkit](https://github.com/prompt-toolkit/python-prompt-toolkit) (`python3-prompt-toolkit` or `pip install prompt_toolkit`), for the CLI
- Optional: [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) on your `$PATH` (`pip install ROPgadget`), for the `load` command that extracts gadgets from a binary
- Optional: [rp++](https://github.com/0vercl0k/rp), to produce gadget files for `load_rp`

## Build

```bash
make -j4           # bin/libropium.so, bin/tests and the Python module bin/ropium.so
./bin/tests        # unit tests (~15 s)
```

Options: `make DEBUG=1` (debug build), `make BINDINGS=0` (no Python module), and the opt-in
`OPT=3`, `LTO=1`, `NATIVE=1`. **Run `make clean` after pulling or changing options**: the Makefile doesn't
track header dependencies. Details in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Install

```bash
make install PREFIX=$HOME/.local
```

This installs the `ropium` CLI in `~/.local/bin`, the library and header in `~/.local/lib` and
`~/.local/include`, and the Python module in your user site-packages. The module always goes to the
site-packages of the user who runs `make install`, so avoid `sudo make install` unless only root will use
ROPium.

You don't need to install anything to use ROPium from the source tree: run the CLI with
`PYTHONPATH=bin python3 cli-tool/ropium`, and add `bin` to `sys.path` in scripts.

# Usage

## CLI tool

```bash
ropium                                      # after installing
PYTHONPATH=bin python3 cli-tool/ropium      # from the source tree
```

```
(ropium)> load_rp samples/gadgets/efssetup.txt   # load a gadget file (or: load -a X86 <binary>, needs ROPgadget)
(ropium)> badbytes set 0x0a 0x0d                 # bytes the chain must not contain
(ropium)> keepregs set edi                       # registers the chain must not modify
(ropium)> timeout set 5                          # give up a search after 5 s
(ropium)> find ecx = edx                         # compile a query

	0x004027af (mov eax, edx; ret)
	0x0040509e (mov ecx, eax; lea esi, [ebp - 0x48]; ret)

(ropium)> help find                              # help on a command
```

| Command | Usage |
|---|---|
| `load` | `load [-a X86\|X64] <binary> [...]`: extract gadgets with ROPgadget |
| `load_rp` | `load_rp [-a X86\|X64] <file>`: load an rp++ or ROPgadget dump file (default X86; use upper case) |
| `find` | `find <query>`: compile a [query](#query-language) and print the chain |
| `badbytes` | `badbytes set <byte> ...` / `badbytes reset` |
| `keepregs` | `keepregs set <reg> ...` / `keepregs reset` |
| `safemem` | `safemem set` (default) / `safemem unset` |
| `abi` | `abi set X86_CDECL\|X86_STDCALL\|X64_SYSTEM_V\|X64_MS` (for function calls) |
| `os` | `os set LINUX\|WINDOWS` (for syscalls) |
| `timeout` | `timeout set <seconds>` / `timeout reset` (no limit, the default) |
| `maxtries` | `maxtries set <n>` / `maxtries reset` (3000) |
| `help` | `help [command]` |
| `exit` | quit (Ctrl+D also works) |

Notes:

- `find` removes all spaces from the query before compiling it.
- `badbytes set` reads `10` as decimal (0x0a); write bytes with the `0x` prefix to avoid surprises.
- Ctrl+C during a `find` stops the search and prints `No ROPChain found.`
- When a search hits the timeout, the CLI says so instead of printing `No ROPChain found.`

## Python API

```python
import sys; sys.path.insert(0, "bin")   # only when running from the source tree
from ropium import ROPium, ARCH, ABI, OS

rop = ROPium(ARCH.X86)                  # or ARCH.X64
rop.load_rp("samples/gadgets/efssetup.txt")   # or rop.load("program.exe") with ROPgadget installed

rop.bad_bytes = [0x0a, 0x0d]           # constraints persist across compile() calls
rop.keep_regs = ["esi", "edi"]
rop.safe_mem = True
rop.abi = ABI.X86_CDECL                 # needed for function calls
rop.os = OS.LINUX                       # needed for syscalls
rop.timeout = 5                         # seconds per compile(), None = no limit

chain = rop.compile("eax = 0x1234")     # a chain, or None
if chain is None:
    print("timed out" if rop.timed_out else "no chain found")
else:
    print(chain.dump())                 # pretty text
    payload = chain.dump("raw")         # bytes, little-endian words
```

| Member | Description |
|---|---|
| `ROPium(arch)` | create a ROPium object for `ARCH.X86` or `ARCH.X64` |
| `rop.load(path)` | extract and analyse the gadgets of a binary (runs ROPgadget) |
| `rop.load_rp(path)` | analyse the gadgets of an rp++ or ROPgadget dump file |
| `rop.compile(query)` | return a chain, or `None`; raises `ValueError` for a malformed query and `RuntimeError` for errors such as a missing ABI |
| `rop.bad_bytes` | list of ints (0-255) that must not appear in the chain |
| `rop.keep_regs` | list of register names (lower case) the chain must not modify |
| `rop.safe_mem` | `True` (default): don't use gadgets that dereference registers which aren't known to hold valid addresses |
| `rop.abi`, `rop.os` | `ABI.X86_CDECL`, `ABI.X86_STDCALL`, `ABI.X64_SYSTEM_V`, `ABI.X64_MS` / `OS.LINUX`, `OS.WINDOWS` |
| `rop.timeout` | seconds per `compile()` call (float), `None` (default) for no limit |
| `rop.max_tries` | number of strategies tried per search (default 3000) |
| `rop.timed_out` | read-only: `True` if the last `compile()` returned `None` because of the timeout |
| `chain.dump(fmt, tab, color)` | `fmt` is `'pretty'` (default), `'raw'` (bytes) or `'python'`; arguments are positional; pass `color=False` (third argument) to drop the ANSI colors |
| `chain1 + chain2` | concatenate two chains |

With the bundled samples, this prints `pop eax; ret` followed by `0x00001234`. Note that every address in
the samples starts with `0x00`, so `0x00` can't be a bad byte with them.

Keep the `ROPium` object alive while you use its chains. The `'python'` format writes a Python-2-style
`struct.pack` script; for payloads, prefer `dump('raw')`.

## Query language

One instruction per line (separate lines with `\n` in Python):

```
eax = 0x42                    # set a register to a constant
eax = ebx                     # copy a register
eax = ebx ^ 3                 # register OP constant
eax = ebx & ecx               # register OP register
eax = [ebx + 16]              # load from memory
eax = [0x12345678]            # load from a constant address
eax += [ebx + 16]             # register OP= memory
[eax - 8] = ebx               # store a register
[eax + 4] = 0x42              # store a constant
[eax + 4] += ebx              # memory OP= register
[0x12345678] = '/bin/sh\x00'  # write a string (constant address only)
0x08040120(1, 2, 3)           # call a function (set an ABI first)
sys_0xb(0x1234, 0, 0)         # Linux syscall by number (set the OS first)
sys_execve(0x1234, 0, 0)      # Linux syscall by name (x64 numbering, see below)
syscall                       # just a syscall gadget
```

- Operators: `+ * / % & | ^ << >>`. There is no `-` operator: write `eax = ebx + -3`. `OP=` only works with
  a memory operand (`eax += [ebx]` works, `eax += 2` doesn't).
- Registers are lower case. Constants are decimal or hexadecimal (`0x...`), possibly negative.
- Lines are compiled one after the other, independently: check that a later line doesn't clobber what an
  earlier one set.
- Syscall names use the x64 Linux numbers even on x86 ([known issue](docs/KNOWN_ISSUES.md#1-chains-that-are-wrong-at-runtime)):
  use `sys_<number>` on x86.

## Constraints and search limits

| Constraint | Python | CLI |
|---|---|---|
| Bytes that must not appear in addresses, constants or padding | `rop.bad_bytes = [0x00, 0x0a]` | `badbytes set 0x00 0x0a` |
| Registers that must keep their value | `rop.keep_regs = ["esi"]` | `keepregs set esi` |
| Memory safety (on by default) | `rop.safe_mem = False` to allow any dereference | `safemem unset` |
| Calling convention for function calls | `rop.abi = ABI.X86_STDCALL` | `abi set X86_STDCALL` |
| Target OS for syscalls | `rop.os = OS.LINUX` | `os set LINUX` |
| Time limit per query | `rop.timeout = 5` | `timeout set 5` |
| Strategies tried per search | `rop.max_tries = 3000` | `maxtries set 3000` |

When no chain exists, ROPium usually proves it quickly. Some searches still explore many combinations
(minutes on large gadget sets), which is what `timeout` is for. `None` with `rop.timed_out == False` means
the search finished without finding a chain.

# Gadget sources

ROPium re-analyses the raw bytes of every gadget itself, so you can feed it gadgets in two ways:

- **`load <binary>`** runs `ROPgadget --binary <binary> --dump --all --depth 15` (ROPgadget must be on `PATH`;
  otherwise nothing is loaded).
- **`load_rp <file>`** reads a gadget listing that includes the gadget bytes, as produced by
  [rp++](https://github.com/0vercl0k/rp) with `--print-bytes` or by `ROPgadget --dump`. This is handy to
  analyse Windows binaries from Linux, or to reuse a listing.

Both fill the same gadget database, so you can mix sources (e.g. a program and a DLL it loads). The
architecture is fixed when the `ROPium` object is created and must match the gadgets.

**Bundled samples** (`samples/`):

| File | Format | From |
|---|---|---|
| `gadgets/efssetup.txt` | ROPgadget `--dump` | `binaries/efssetup.exe` |
| `gadgets/vulnserver_3.txt` | ROPgadget `--dump` | `binaries/vulnserver.exe` |
| `gadgets/mp3_conf.txt` | rp++ | RM2MP3Converter.exe (not included) |
| `gadgets/ImageLoad.txt` | rp++ | ImageLoad.dll (not included) |
| `tools/rp-win_x86_v6.exe` | rp++ v2.1.5, Windows x86 build (runs under Wine) | |

**Generating a file with rp++**:

```bash
rp-win_x86_v6.exe -f program.exe -r 10 --print-bytes --unique > program.txt
```

`--print-bytes` is required (the bytes are the last field of each line); `-r` sets the maximum number of
instructions per gadget, and `--unique` keeps one line per gadget. Accepted line formats:

```
0x4236a3: aaa ; add [eax], eax ; pop edi ; pop esi ; ret ; \x37\x3e\x01\x00\x5f\x5e\xc3 (1 found)   # rp++
0x00403e23 : aaa ; xor eax, eax ; jmp 0x403e30 // 37383941424344454633c0eb00                      # ROPgadget --dump
```

Notes:

- The file must be UTF-8: rp++ output redirected by PowerShell is UTF-16, so convert it first
  (`iconv -f utf-16 -t utf-8 in.txt > out.txt`).
- Gadget addresses must currently be below `0x80000000` (see [known limitations](#known-limitations)).

# Docker

The image builds ROPium and starts the CLI:

```bash
docker build . --tag ropium
docker run --rm -it -v "$(pwd)/samples":/samples:ro ropium
```

```
(ropium)> load_rp /samples/gadgets/efssetup.txt
(ropium)> find ecx = edx
```

Mount the directory holding your own gadget files or binaries the same way. The image doesn't contain a
compiler: rebuild it after changing the code.

# How it works

ROPium is a **ROP-chain compiler**:

1. **Analysis.** Each gadget is disassembled (Capstone), lifted to an intermediate representation and
   executed symbolically. Gadgets with a known stack effect that end in `ret`, `jmp reg`, `call reg` or a
   syscall are filed in a database indexed by what they compute (`reg <- reg`, `reg <- [reg + off]`,
   `[reg + off] <- reg`, ...).
2. **Compilation.** A query becomes a small graph of abstract gadget slots. ROPium searches for real
   gadgets that fill the slots while respecting the constraints. When that fails, it rewrites the graph
   into alternatives (go through another register, pop the constant from the stack, end with `jmp reg`
   instead of `ret`, ...) and tries again, smallest graphs first.

```
binary ──► ROPgadget ─┐
gadget dump file ─────┴─► disassembly → IR → symbolic execution → gadget database
query ──► parser → strategy graph → search (rewrite rules + gadget selection) → ROP chain
```

The full walkthrough is in [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

# Known limitations

The most important ones (full list with details in [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md)):

- **Check the chains you use.** A few gadget shapes are analysed incorrectly, which can yield a wrong
  chain: gadgets that write to the stack and read it back in the same gadget (e.g. `pushal; pop ebx; ret`),
  and some store or arithmetic queries where a gadget clobbers an input register.
- Syscall names use the x64 numbers on x86 (use `sys_<number>`), and `X64_MS` calls use the wrong argument
  registers.
- Gadgets with shifts, rotates, `cmov`, `setcc`, `movsx`, conditional jumps, `ret <n>`, `sbb` or `endbr64`
  are not used.
- Gadget addresses must be below `0x80000000`; higher addresses abort the program.
- An empty query crashes the Python interpreter; `load()` without ROPgadget silently loads nothing.

# Development

Building, unit tests, the chain regression fixture, profiling and the rules for changing the search are
described in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

# Contact

**Boyan MILANOV** - boyan.milanov (at) hotmail (dot) fr

# Licence
ROPium is provided under the MIT licence.

# Special thanks
Contributors:
   -  Docker container support: [migounette](https://github.com/migounette), [clslgrnc](https://github.com/clslgrnc)

ROPium uses the following awesome projects:
   - [capstone](https://github.com/aquynh/capstone) : Disassembly Framework
   - [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) : Gadget extractor
   - [prompt-toolkit](https://github.com/prompt-toolkit/python-prompt-toolkit) : Python CLI interface library
