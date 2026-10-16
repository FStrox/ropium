#ifndef ROP_COMPILER_H
#define ROP_COMPILER_H

#include "strategy.hpp"
#include "il.hpp"
#include "database.hpp"
#include "systems.hpp"
#include <list>
#include <map>

using std::list;

// Default number of strategy graphs that one CompilerTask tries
const int DEFAULT_MAX_TRIES = 3000;

enum class ABI{
    /* X86 */
    X86_CDECL,
    X86_STDCALL,
    X86_FASTCALL,
    X86_THISCALL_GCC,
    X86_THISCALL_MS,
    X86_LINUX_SYSENTER,
    X86_LINUX_INT80,
    /* X64 */
    X64_MS,
    X64_SYSTEM_V,
    /* No specific ABI */
    NONE
};

/* StrategyQueue
   =============

   The pending strategy graphs of a CompilerTask. pop() returns the smallest
   graph first and, among graphs of the same size, the one added last.

   It reproduces exactly the order of the sorted vector it replaces (O(n)
   insert, front = largest graph, pop from the back), including the graphs
   that push_initial() appends without sorting, in O(log k) per operation
   where k is the number of distinct graph sizes in the queue:

   - Graphs are kept in buckets. A bucket's key is the size of its first
     graph; its other graphs are at least that large. In the old vector a
     bucket is a run that starts at a new running minimum (from the front).
   - push() appends a graph to the bucket of its size (the old insert went
     right before the first graph smaller than itself).
   - push_initial() appends to the smallest bucket, or opens a new bucket if
     the graph is smaller than every key (the old vector::push_back).
   - pop() removes the last graph of the smallest bucket (the old back()).

   The queue owns the graphs it holds.
*/
class StrategyQueue{
    std::map<int, vector<StrategyGraph*>> _buckets;
    size_t _size;
public:
    StrategyQueue();
    StrategyQueue(const StrategyQueue& other) = delete;
    StrategyQueue& operator=(const StrategyQueue& other) = delete;
    ~StrategyQueue();
    bool empty() const;
    size_t size() const;
    // Queue a graph translated from the IL (not size ordered)
    void push_initial(StrategyGraph* graph);
    // Queue a graph produced by a strategy rule. If the queue already holds
    // max_tries graphs or more and none of them is larger than 'graph', the
    // graph is rejected: returns false and the caller keeps ownership
    bool push(StrategyGraph* graph, int max_tries);
    // Remove and return the next graph to try (the caller takes ownership)
    StrategyGraph* pop();
    // Delete all queued graphs
    void clear();
};

/* CompilerTask
   ============

   A compiler task is basically a set of StrategyGraph. For each graph,
   it tries to find a valid gadget selection. 

   - If it succeeds, the corresponding ROPChain is returned.
   - If it fails, it applies strategy rules to the graph to create new graphs,
     adds the new graphs to the queue of pending graphs, and then tries the 
     next one

*/

class CompilerTask{
    void apply_rules_to_graph(StrategyGraph* graph, int max_tries);
    Arch * arch;
    StrategyQueue pending_strategies;
public:
    CompilerTask(Arch* arch);
    // Add a graph translated from the IL (the task takes ownership)
    void add_initial_strategy(StrategyGraph* graph);
    void add_strategy(StrategyGraph* graph, int max_tries);
    ROPChain* compile(Arch* arch, GadgetDB* db, Constraint* constraint=nullptr, int nb_tries=DEFAULT_MAX_TRIES);
    void clear();
    ~CompilerTask();
};

/* ROPCompiler
   ============

   A ROP compiler is an abstraction over IL and StrategyGraph functionnalities.
   Basically it takes an IL program, parses it, translates it into strategy 
   graphs, and then start a compiler task to try to satisfy the program and
   find a matching ROPChain.

*/

class ROPCompiler{
    ROPChain* _set_registers_permutation( vector<ILInstruction>& instr, vector<int>& permutation,
        Constraint* constraint, list<vector<int>>& failed_perms, bool& failed_on_first);
    bool is_complex_instr(ILInstruction& instr, ABI abi);
    // compile() without starting a new search deadline (for nested compilations)
    ROPChain* _compile(string program, Constraint* constraint, ABI abi, System sys);
public:
    Arch* arch;
    GadgetDB* db;
    // Search limits. They are members rather than compile() arguments so
    // that every search started by a compile() call uses them
    int max_tries; // Strategy graphs tried per search (CompilerTask), one search per instruction or register to set
    unsigned int timeout_ms; // Wall-clock limit for a whole compile() call, 0 = no limit
    bool last_compile_timed_out; // The last compile() returned nullptr because it reached timeout_ms

    // Translate function calls into strategy graphs
    bool _x86_cdecl_to_strategy(StrategyGraph& graph, ILInstruction& instr);
    bool _x86_stdcall_to_strategy(StrategyGraph& graph, ILInstruction& instr);

    // Compile wrappers for functions and syscalls that set multiple registers
    ROPChain* _set_multiple_registers(vector<ILInstruction>& instr, Constraint* constraint);
    ROPChain* _compile_x86_linux_syscall(ILInstruction& instr, Constraint* constraint);
    ROPChain* _compile_x64_linux_syscall(ILInstruction& instr, Constraint* constraint);
    ROPChain* _compile_x64_system_v_call(ILInstruction& instr, Constraint* constraint);
    ROPChain* _compile_x64_ms_call(ILInstruction& instr, Constraint* constraint);

    ROPCompiler( Arch* arch, GadgetDB* db);

    // Main API
    // Take a list of instructions and compile all of them sequentially into a ropchain
    ROPChain* process_simple(vector<ILInstruction>& instructions, Constraint* constraint=nullptr, ABI abi = ABI::NONE, System sys=System::NONE);
    ROPChain* process_complex(vector<ILInstruction>& instructions, Constraint* constraint=nullptr, ABI abi = ABI::NONE, System sys=System::NONE);
    // Transform complex instructions into simpler instructions that can be handled by "process()"
    bool preprocess(vector<ILInstruction>& dst, vector<ILInstruction>& src, Constraint* constraint=nullptr);
    // Parse a program into a vector of instructions
    vector<ILInstruction> parse(string& program);
    // Translate an IL instruction into one or several strategy graphs
    void il_to_strategy(vector<StrategyGraph*>& graphs, ILInstruction& instr, Constraint* constraint = nullptr, ABI abi = ABI::NONE, System sys=System::NONE);
    // Parse and process a program
    ROPChain* compile(string program, Constraint* constraint=nullptr, ABI abi=ABI::NONE, System sys=System::NONE);
};

#endif
