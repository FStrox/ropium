#!/usr/bin/env python3
"""Compile the README showcase queries against the bundled sample gadget files.

Run it from anywhere after `make`:

    python3 examples/showcase.py

It imports the freshly built module from ../bin when ROPium isn't installed, and
works in a temporary directory because load_rp() writes a temporary file
(./ropium_raw_gadgets.0) into the current directory.
"""
import os
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GADGETS = os.path.join(REPO, "samples", "gadgets")
sys.path.insert(0, os.path.join(REPO, "bin"))

from ropium import ROPium, ARCH, ABI  # noqa: E402

# (title, gadget file, query, settings applied before compiling)
SHOWCASE = [
    ("Move a register through another one", "efssetup.txt", "ecx = edx", {}),
    ("Load a constant", "vulnserver_3.txt", "ebx = 0xdeadbeef", {}),
    ("Store a constant in memory", "efssetup.txt", "[ecx + 4] = 0x1234", {}),
    ("Write a string", "efssetup.txt", r"[0x0804a000] = '/bin/sh\x00'", {}),
    ("Several instructions", "efssetup.txt", "eax = 1\nebx = 2", {}),
    ("Call a function (cdecl)", "efssetup.txt", "0x10001234(1, 2)", {"abi": ABI.X86_CDECL}),
    ("Call a function (stdcall)", "efssetup.txt", "0x10001234(1, 2)", {"abi": ABI.X86_STDCALL}),
    ("Gadget ending with 'call'", "mp3_conf.txt", "ebx = eax", {}),
    ("Constraints change the chain", "efssetup.txt", "ecx = edx", {"bad_bytes": [0xaf]}),
    ("Impossible query fails fast", "efssetup.txt", "eax = ebx + ecx", {}),
    ("Bounded search", "efssetup.txt", "eax = [ebx + 4]", {"timeout": 2}),
]


ABI_NAMES = {ABI.X86_CDECL: "ABI.X86_CDECL", ABI.X86_STDCALL: "ABI.X86_STDCALL"}


def describe(settings):
    """Settings as the Python statements that set them"""
    parts = []
    for name, value in settings.items():
        if name == "abi":
            value = ABI_NAMES[value]
        elif name == "bad_bytes":
            value = "[%s]" % ", ".join("0x%02x" % b for b in value)
        parts.append("rop.%s = %s" % (name, value))
    return "; ".join(parts)


def main():
    old_cwd = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="ropium_showcase_") as workdir:
        os.chdir(workdir)
        try:
            run_showcase()
        finally:
            os.chdir(old_cwd)


def run_showcase():
    loaded = {}
    for title, gadget_file, query, settings in SHOWCASE:
        if gadget_file not in loaded:
            rop = ROPium(ARCH.X86)
            rop.load_rp(os.path.join(GADGETS, gadget_file))
            loaded[gadget_file] = rop
        rop = loaded[gadget_file]
        # Reset the constraints shared by queries on the same gadget file
        rop.bad_bytes = settings.get("bad_bytes", [])
        rop.abi = settings.get("abi", ABI.NONE)
        rop.timeout = settings.get("timeout", 30)

        start = time.perf_counter()
        chain = rop.compile(query)
        elapsed = time.perf_counter() - start

        print("\n### %s: %s, %r %s" % (title, gadget_file, query, describe(settings)))
        if chain is not None:
            print(chain.dump("pretty", "", False), end="")
        elif rop.timed_out:
            print("None after %.1f s: rop.timed_out is True" % elapsed)
        else:
            print("None after %.1f s: the search finished without a chain" % elapsed)


if __name__ == "__main__":
    main()
