CC = gcc
CXX = g++

OUTDIR = ./bin
LIB_FILE = libropium.so
LIB_HEADER_FILE = ropium.hpp
BINDINGS_FILE = ropium.so

## Basic default flags 
CFLAGS ?=
CXXFLAGS ?=
LDFLAGS ?=
LDLIBS ?=
LDLIBS += -lcapstone

## Flags for debug mode
## (OPT, see the opt-in flags below, only applies to non-debug builds: DEBUG=1 wins)
DEBUG ?= 0
OPT ?= 2
ifeq ($(DEBUG), 1)
	CFLAGS += -g -O0
	CXXFLAGS += -g -O0
	LDFLAGS += -g
else
	CFLAGS += -O$(OPT)
	CXXFLAGS += -O$(OPT) -Wno-narrowing
endif

## Profiling with gprof (opt-in): make PROFILE=1 BINDINGS=0 bench
PROFILE ?= 0
ifeq ($(PROFILE), 1)
	CFLAGS += -pg
	CXXFLAGS += -pg
	LDFLAGS += -pg
endif

## Bindings
BINDINGS ?= 1
ifeq ($(BINDINGS), 1)
	CXXFLAGS += `python3-config --cflags` -DPYTHON_BINDINGS -Ibindings/python
	BINDINGS_DIR = ./bindings
	BINDINGS_SRCS = $(wildcard $(BINDINGS_DIR)/*.cpp)
	BINDINGS_OBJS = $(BINDINGS_SRCS:.cpp=.o)
	BINDINGS_RULE = bindings
	LDLIBS += `python3-config --libs`
else
	BINDINGS_RULE = 
endif

## Opt-in optimization flags (not used by default): make NATIVE=1 LTO=1 OPT=3
##   NATIVE=1  -march=native: use the build CPU's instruction set (binaries may not run on other CPUs)
##   LTO=1     link-time optimization (-flto=auto on compile and link lines)
##   OPT=3     -O3 instead of -O2 in non-debug builds (DEBUG=1 wins and keeps -g -O0).
##             `python3-config --cflags` above ends with its own -O2 and the last -O wins,
##             so a non-default OPT is repeated after it.
NATIVE ?= 0
ifeq ($(NATIVE), 1)
	CFLAGS += -march=native
	CXXFLAGS += -march=native
endif
LTO ?= 0
ifeq ($(LTO), 1)
	CFLAGS += -flto=auto
	CXXFLAGS += -flto=auto
	LDFLAGS += -flto=auto
endif
ifneq ($(DEBUG), 1)
ifneq ($(OPT), 2)
	CXXFLAGS += -O$(OPT)
endif
endif

SRCDIR=./libropium

## Final C++ flags
CXXFLAGS += -std=c++11 -fpermissive -fPIC -I $(SRCDIR)/include -I $(SRCDIR)/dependencies/murmur3 -Wno-write-strings -Wno-sign-compare -Wno-reorder

# Source files
SRCS=$(wildcard $(SRCDIR)/symbolic/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/ir/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/arch/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/ropchain/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/utils/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/database/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/compiler/*.cpp)
OBJS=$(SRCS:.cpp=.o)

TESTDIR = ./tests
TESTSRCS = $(wildcard $(TESTDIR)/*.cpp)
TESTOBJS = $(TESTSRCS:.cpp=.o)

# Profiling driver (not part of 'all' nor of the unit tests)
BENCHDIR = $(TESTDIR)/bench
BENCHSRCS = $(BENCHDIR)/bench.cpp
BENCHOBJS = $(BENCHSRCS:.cpp=.o)

DEPDIR = $(SRCDIR)/dependencies
DEPSRCS = $(DEPDIR)/murmur3/murmur3.c 
DEPOBJS = $(DEPSRCS:.c=.o)

INCLUDEDIR = $(SRCDIR)/include

# Compile lib and tests 
all: lib tests $(BINDINGS_RULE)

# librop
lib: $(OBJS) $(DEPOBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/$(LIB_FILE) -shared $(OBJS) $(DEPOBJS) $(LDLIBS)

# unit tests
tests: $(TESTOBJS) $(OBJS) $(DEPOBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/tests $(TESTOBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

# bindings
bindings: $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/$(BINDINGS_FILE) -shared $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

# profiling driver (see tests/bench/profile.sh)
.PHONY: bench
bench: $(BENCHOBJS) $(OBJS) $(DEPOBJS)
	@mkdir -p $(OUTDIR)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/bench $(BENCHOBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

# generic
%.o : %.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c $< -o $@ $(LDLIBS)

%.o : %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@ $(LDLIBS)

# Installation (assuming Linux system) 
# If prefix not set, set default
ifeq ($(PREFIX),)
    PREFIX = /usr
endif

INSTALL_MESSAGE_RULE=
# Check if lib and binding files exist
ifneq (,$(wildcard ./bin/$(LIB_FILE)))
    INSTALL_LIB_RULE=install_lib
	INSTALL_MESSAGE_RULE=print_install_message
else
	INSTALL_LIB_RULE=
endif
ifneq (,$(wildcard ./bin/$(BINDINGS_FILE))) 
    INSTALL_BINDINGS_RULE=install_bindings
    PYTHONDIR=$(shell python3 -m site --user-site)/
	INSTALL_MESSAGE_RULE=print_install_message
else
	INSTALL_BINDINGS_RULE=
endif

# make install command
install: $(INSTALL_LIB_RULE) $(INSTALL_BINDINGS_RULE) install_cli_tool $(INSTALL_MESSAGE_RULE)

install_lib:
	install -d $(DESTDIR)$(PREFIX)/lib/
	install -D $(OUTDIR)/$(LIB_FILE) $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/
	install -D $(INCLUDEDIR)/$(LIB_HEADER_FILE) $(DESTDIR)$(PREFIX)/include/

install_bindings:
	install -d $(PYTHONDIR)
	install -D $(OUTDIR)/$(BINDINGS_FILE) $(PYTHONDIR)

install_cli_tool:
	install -d $(DESTDIR)$(PREFIX)/bin/
	install -D cli-tool/ropium $(DESTDIR)$(PREFIX)/bin/

print_install_message:
	@echo "\nROPium was successfully installed."

# make test command
test:
	$(OUTDIR)/tests

# cleaning 
cleanall: clean

clean:
	rm -f $(OBJS)
	rm -f $(DEPOBJS)
	rm -f $(TESTOBJS)
	rm -f $(BENCHOBJS)
	rm -f $(BINDINGS_OBJS)
	rm -f `find . -type f -name "*.gch"`
	rm -f $(OUTDIR)/*
