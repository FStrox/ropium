

<p align="center" >
<img width=50% src="/ressources/ropium_logo.png"/><br /><br /><br />
</p>

# About
**ROPium** (ex-ROPGenerator) is a library/tool that makes ROP-exploits easy. It automatically extracts and analyses gadgets from binaries and
lets you find ROP-chains with semantic queries. ROPium supports *X86* and *X64* architectures, soon to be 
extended with *ARM*.

Key features:

   - **Effortless**: ROPium works out-of-the-box with a smooth Command Line Interface
   - **Python API**: It is easy to integrate ROPium in script thanks to its python API
   - **Automatic chaining**: ROPium automatically combines gadgets to create complex ROP-chains
   - **Advanced features**: ROPium supports function calls for various ABIs, syscalls, ...
   - **Semantic queries**: ROPium queries are quick and convenient to write : ``rax=rbx+8``, ``[rdi+0x20]=rax``, ``rsi=[rbx+16]``, ``0x08040212(1, 2, rax)``, ``[0xdeadbeaf] = "/bin/sh\x00"``, ``sys_execve(0xdeadbeef, 0, 0)``, ``sys_0x1(0)``, ``...``


# Content
- [About](#about)
- [Installation](#installation)
- [Getting started](#getting-started)
   - [CLI tool](#cli-tool)
   - [Python API](#python-api)
- [Docker](#docker)
- [Contact](#contact)
- [Licence](#licence)
- [Special thanks](#special-thanks)

# Getting started

### CLI tool

Thanks to a Command-Line-Interface wrapper, you can use ROPium interactively to quickly build ropchains:  

<p align="center">
  <img src="/ressources/ropium.gif" width="800" align="middle">
</p>

### Python API

Do you need to integrate ropchains directly in your scripts ? Good news, ROPium has a python API !

Loading a binary and finding ropchains:
```Python
from ropium import *
rop = ROPium(ARCH.X64)
rop.load('/lib/x86_64-linux-gnu/libc-2.27.so')

chain = rop.compile('rbx = [rax + 0x20]')
```

Dumping a ropchain in various formats:
```Python
>>> print( chain.dump() )

0x000000000009a851 (sub rax, 0x10; ret)
0x0000000000130018 (mov rax, qword ptr [rax + 0x30]; ret)
0x0000000000052240 (push rax; pop rbx; ret)

>>> print(chain.dump('python'))

from struct import pack
off = 0x0
p = ''
p += pack('<Q', 0x000000000009a851+off) # sub rax, 0x10; ret
p += pack('<Q', 0x0000000000130018+off) # mov rax, qword ptr [rax + 0x30]; ret
p += pack('<Q', 0x0000000000052240+off) # push rax; pop rbx; ret

>>> print(chain.dump('raw'))

b'Q\xa8\t\x00\x00\x00\x00\x00\x18\x00\x13\x00\x00\x00\x00\x00@"\x05\x00\x00\x00\x00\x00'
```

Set constraints on ropchains:
```Python
# Bytes that should not appear in the ropchain
rop.bad_bytes = [0x00, 0x0a, 0x0b]

# Register that should not be clobbered by the ropchain
rop.keep_regs = ['rsi', 'rdx']

# Enable/Forbid ropchain to dereference registers that might hold invalid addresses
# Safe mode is 'True' by default
rop.safe_mem = False

# Specify which ABI you want to use when calling functions
rop.abi = ABI.X86_CDECL

# Specify which system to target when doing syscalls
rop.os = OS.LINUX
```

# How it works

ROPium is a **ROP-chain compiler**: you describe *what* you want a chain to achieve with a semantic query
(e.g. `eax = 0x1234`, `[eax-8] = ebx`, `sys_execve(0x1234, 0, 0)`) and it searches its gadget database
for a gadget sequence that satisfies it, honoring constraints (bad bytes, registers to preserve, memory safety).

```
binary ──► gadget extraction (ROPgadget) ─┐
rp++ dump ─► gadget ingestion (load_rp) ──┴─► disassembly (Capstone) → IR → symbolic execution
             → typed gadget database → query (IL) → StrategyGraph search → ROPChain
```

A detailed walkthrough of the internals (analysis pipeline, gadget database, query language,
strategy rules, rp++ file format parsing) is available in [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

# Installation

## Requirements

- `g++` / `gcc`, `make`
- [Capstone](https://www.capstone-engine.org/) (`libcapstone-dev`)
- Python 3 headers (`python3-dev`, for the bindings)
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) on your `$PATH` (`pip install ROPgadget`) —
  used by the `load` command to extract gadgets from binaries
- Optionally [rp++](https://github.com/0vercl0k/rp) to pre-generate gadget files (see below)

## Build & install

```bash
make            # builds bin/libropium.so, bin/tests and the Python module bin/ropium.so
make install    # installs the lib, headers, Python module and the 'ropium' CLI
```

Use `make DEBUG=1` for a debug build, `make BINDINGS=0` to skip the Python bindings, and
`make test` to run the unit tests.

# Usage

## CLI tool

```bash
ropium
```

```
(ropium)> load -a X86 ./samples/binaries/efssetup.exe   # extract gadgets from a binary (uses ROPgadget)
(ropium)> badbytes set 0x0a 0x00                        # avoid these bytes in the chain
(ropium)> keepregs set esi                              # don't clobber esi
(ropium)> find eax = 0x1234                             # compile a semantic query
```

Main commands: `load`, `load_rp`, `find`, `badbytes`, `keepregs`, `safemem`, `abi`, `os`, `help`, `exit`.

## Python API

```python
from ropium import ROPium, ARCH, ABI, OS

rop = ROPium(ARCH.X86)
rop.load('./samples/binaries/efssetup.exe')   # gadget extraction via ROPgadget
# or: rop.load_rp('samples/gadgets/efssetup.txt')  # load a pre-generated rp++ file (see below)

rop.bad_bytes = [0x0a, 0x0d]                  # constraints
rop.keep_regs = ["eax"]
rop.safe_mem = True
rop.abi = ABI.X86_STDCALL
rop.os = OS.WINDOWS

chain = rop.compile('eax = 0x1234')
print(chain.dump())          # pretty
print(chain.dump('python')) # struct.pack snippet
print(chain.dump('raw'))    # raw bytes for your payload
```

See `RopChainer.py` for a runnable example.

## Query language

```
eax = 0x42                    # set register to constant
eax = ebx ^ 3                 # register arithmetic/logic ops
eax = [ebx + 16]              # load from memory
[eax - 8] = ebx               # store to memory
[0x12345678] = '/bin/sh\x00'  # write a string
0x08040120(1, 2, 3)           # call function (requires 'abi set ...')
sys_execve(0x1234, 0, 0)      # Linux syscall by name (requires 'os set LINUX')
sys_0xb(0x1234, 0, 0)         # Linux syscall by number
```

# Using rp++ gadget files

ROPium can ingest gadget listings produced by [rp++](https://github.com/0vercl0k/rp)
(a fast ROP gadget finder for PE/ELF/Mach-O binaries) instead of running ROPgadget itself.
This is handy to analyze Windows binaries from Linux, to reuse an existing rp++ dump, or to
mix gadget sources. The `samples/` folder already demonstrates this integration:

- `samples/tools/rp-win_x86_v6.exe` — bundled rp++ v2.1.5 (x86 Windows build; run it with Wine)
- `samples/binaries/*.exe` — sample PE32 targets (`efssetup.exe`, `QuoteDB.exe`, `vulnserver.exe`)
- `samples/gadgets/*.txt` — pre-generated rp++ dumps of those binaries, ready for `load_rp`

## Step 1 — Generate a gadget file with rp++

```bash
# Windows (or via Wine on Linux):
rp-win_x86_v6.exe -f efssetup.exe -r 10 --print-bytes > efssetup.txt

# Recommended: deduplicate gadgets for a smaller/faster load
rp-win_x86_v6.exe -f efssetup.exe -r 10 --print-bytes --unique > efssetup.txt
```

**`--print-bytes` is required**: ROPium re-disassembles the raw bytes of each gadget itself,
so the listing must contain them. Useful rp++ flags:

| Flag | Meaning |
|---|---|
| `-f, --file <path>` | binary to analyze |
| `-r, --rop <n>` | max instructions per gadget (default 5) |
| `--print-bytes` | print gadget bytes (**required for ROPium**) |
| `--unique` | keep only unique gadgets |
| `--va <base>` | override the image base address |
| `--raw` | analyze a raw file |
| `--allow-branches` | allow branches inside gadgets |
| `--max-thread <n>` | cap worker threads |

The resulting file looks like (both formats below are accepted):

```
0x00403e23 : aaa ; xor eax, eax ; jmp 0x403e30 // 37383941424344454633c0eb00
0x4236a3: aaa ; add [eax], eax ; pop edi ; pop esi ; ret ; \x37\x3e\x01\x00\x5f\x5e\xc3 (1 found)
```

## Step 2 — Load the gadgets in ROPium

CLI:

```
(ropium)> load_rp samples/gadgets/efssetup.txt
(ropium)> find eax = 0x1234
```

Python:

```python
rop = ROPium(ARCH.X86)
rop.load_rp('samples/gadgets/efssetup.txt')
chain = rop.compile('eax = 0x1234')
```

Notes:

- The architecture is fixed when creating the `ROPium` object (`ARCH.X86` for the 32-bit
  samples); make sure the rp++ dump matches it.
- `load` (ROPgadget) and `load_rp` (rp++) fill the same gadget database, so you can mix
  sources — e.g. load a binary plus an rp++ dump of a DLL it uses.
- rp++ is only used offline to produce the text file; ROPium performs its own semantic
  analysis of the gadget bytes.

# Docker

If needed you can run ROPium in a docker container. The container can be generated from the *Dockerfile* as
follows:

```bash
# Create your docker image (this will take time!)
docker build . --tag ropium

# Run the image in interactive mode, bind mounting the file to analyze
docker run --rm -it -v /FULL/HOST/PATH/FILE:/tmp/FILE:ro ropium
# ex. docker run --rm -it -v ./ropium/:/ropium/ ropium)
cd /ropium/
make clean && make && make install
ropium

# Analyse a file with ROPium
(ropium)> load -a X86 /tmp/FILE
```
The actual image is around 200 MB based on a Debian Stretch with a Python 3.7.3 installed. 

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

