#include "compiler.hpp"
#include "arch.hpp"
#include "exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>

using std::cout;
using std::endl;
using std::string;

namespace test{
    namespace compiler{
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush;
                throw test_exception();
            }
            return 1;
        }

        unsigned int _assert_ropchain(ROPChain* ropchain, const string& msg){
            if( ropchain == nullptr){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            delete ropchain;
            return 1; 
        }
        
        unsigned int _assert_no_ropchain(ROPChain* ropchain, const string& msg){
            if( ropchain != nullptr){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1;
        }

        /* Reference model for StrategyQueue: the pending-strategy vector that
           CompilerTask used before (sorted by decreasing size except for the
           initial graphs, which were appended unsorted; popped from the back) */
        class LegacyStrategyQueue{
        public:
            vector<StrategyGraph*> graphs;
            void push_initial(StrategyGraph* graph){
                graphs.push_back(graph);
            }
            bool push(StrategyGraph* graph, int max_tries){
                vector<StrategyGraph*>::iterator g;
                // !graphs.empty(): the old code read front() of an empty vector there
                if( graphs.size() >= max_tries && !graphs.empty() && graphs.front()->size <= graph->size ){
                    return false;
                }
                for( g = graphs.begin(); g != graphs.end() && (*g)->size >= graph->size; g++ ){}
                graphs.insert(g, graph);
                return true;
            }
            StrategyGraph* pop(){
                StrategyGraph* graph = graphs.back();
                graphs.pop_back();
                return graph;
            }
        };

        StrategyGraph* _new_graph_of_size(int size){
            StrategyGraph* graph = new StrategyGraph();
            graph->size = size;
            return graph;
        }

        unsigned int strategy_queue_order(){
            unsigned int nb = 0;
            StrategyQueue queue;
            vector<StrategyGraph*> g;
            bool got_exception = false;

            // Smallest first, last added first among equal sizes
            for( int size : {3, 1, 2, 1, 3} ){
                g.push_back(_new_graph_of_size(size));
                queue.push(g.back(), 3000);
            }
            for( int i : {3, 1, 2, 4, 0} ){
                StrategyGraph* popped = queue.pop();
                nb += _assert(popped == g[i], "StrategyQueue: wrong pop order for sorted pushes");
                delete popped;
            }
            nb += _assert(queue.empty(), "StrategyQueue: should be empty");
            g.clear();

            // Initial graphs are not sorted: old vector [2, 5, 1], pop 1, insert 3 at the front
            for( int size : {2, 5, 1} ){
                g.push_back(_new_graph_of_size(size));
                queue.push_initial(g.back());
            }
            nb += _assert(queue.pop() == g[2], "StrategyQueue: wrong pop order for initial graphs");
            delete g[2];
            g.push_back(_new_graph_of_size(3));
            queue.push(g.back(), 3000);
            for( int i : {1, 0, 3} ){
                StrategyGraph* popped = queue.pop();
                nb += _assert(popped == g[i], "StrategyQueue: wrong pop order after initial graphs");
                delete popped;
            }
            g.clear();

            // Reject rule: full and no queued graph larger than the new one
            for( int size : {2, 4} ){
                g.push_back(_new_graph_of_size(size));
                queue.push(g.back(), 3000);
            }
            StrategyGraph* big = _new_graph_of_size(4);
            nb += _assert(!queue.push(big, 2), "StrategyQueue: should reject a graph when full");
            delete big;
            nb += _assert(queue.push(_new_graph_of_size(3), 2), "StrategyQueue: should accept a smaller graph when full");
            nb += _assert(queue.size() == 3, "StrategyQueue: wrong size");
            queue.clear();
            nb += _assert(queue.empty(), "StrategyQueue: should be empty after clear()");

            try{
                queue.pop();
            }catch(runtime_exception& e){
                got_exception = true;
            }
            nb += _assert(got_exception, "StrategyQueue: pop() on an empty queue should throw");

            return nb;
        }

        // Drive StrategyQueue and the legacy vector with the same random
        // operations and check that they pop the same graphs in the same order.
        // Both hold the same graph pointers: a graph is deleted only once both
        // have dropped it, so a mismatch leaks instead of double freeing.
        unsigned int strategy_queue_equivalence(){
            unsigned int nb = 0;
            std::mt19937 rng(0x5eed); // Fixed seed: reproducible

            for( int round = 0; round < 100; round++ ){
                StrategyQueue queue;
                LegacyStrategyQueue legacy;
                StrategyGraph* graph;
                bool same = true;
                int nb_sizes = 1 + rng() % 12; // Few distinct sizes -> many ties
                int budget = rng() % 80; // Remaining tries, as in CompilerTask::compile()

                for( int i = rng() % 5; i > 0; i-- ){
                    graph = _new_graph_of_size(rng() % nb_sizes);
                    queue.push_initial(graph);
                    legacy.push_initial(graph);
                }
                for( int op = 0; op < 500 && same; op++ ){
                    unsigned int r = rng() % 100;
                    if( r < 30 ){
                        // Pop (one try)
                        if( legacy.graphs.empty() ){
                            same = queue.empty();
                            continue;
                        }
                        graph = legacy.pop();
                        same = (queue.pop() == graph);
                        if( same )
                            delete graph;
                        if( budget > 0 )
                            budget--;
                    }else if( r < 33 ){
                        // Initial graph, at any time
                        graph = _new_graph_of_size(rng() % nb_sizes);
                        queue.push_initial(graph);
                        legacy.push_initial(graph);
                    }else{
                        // Rule-derived graph, capped by the remaining budget
                        graph = _new_graph_of_size(rng() % nb_sizes);
                        bool queued = legacy.push(graph, budget);
                        same = (queue.push(graph, budget) == queued);
                        if( same && !queued )
                            delete graph;
                    }
                    same = same && (queue.size() == legacy.graphs.size());
                }
                // Drain both
                while( same && !legacy.graphs.empty() ){
                    graph = legacy.pop();
                    same = (queue.pop() == graph);
                    if( same )
                        delete graph;
                }
                same = same && queue.empty();
                nb += _assert(same, QuickFmt() << "StrategyQueue differs from the legacy vector in round " << round >> QuickFmt::to_str);
            }
            return nb;
        }

        void _wait_ms(int ms){
            auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
            while( std::chrono::steady_clock::now() < until ){}
        }

        unsigned int search_deadline(){
            unsigned int nb = 0;
            bool seen = false;

            set_search_deadline(0);
            nb += _assert(!is_search_deadline_reached() && !poll_search_deadline(), "Search deadline: 0 should mean no deadline");

            set_search_deadline(60000);
            nb += _assert(!is_search_deadline_reached(), "Search deadline: reached too early");

            set_search_deadline(1);
            _wait_ms(5);
            nb += _assert(!search_deadline_was_reached(), "Search deadline: reported reached before any check");
            nb += _assert(is_search_deadline_reached(), "Search deadline: not reached after it expired");
            nb += _assert(search_deadline_was_reached() && poll_search_deadline(), "Search deadline: should stay reached");
            unset_search_deadline();
            nb += _assert(!search_deadline_was_reached() && !is_search_deadline_reached(), "Search deadline: unset should clear it");

            // The throttled poll reads the clock eventually
            set_search_deadline(1);
            _wait_ms(5);
            for( int i = 0; i < 100000 && !seen; i++ ){
                seen = poll_search_deadline();
            }
            nb += _assert(seen, "Search deadline: poll never saw the deadline");
            unset_search_deadline();

            return nb;
        }

        unsigned int search_limits(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            vector<RawGadget> raw;
            vector<StrategyGraph*> graphs;
            string query;

            raw.push_back(RawGadget(string("\x89\xf9\xc3", 3), 1)); // mov ecx, edi; ret
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 2)); // mov eax, ecx; ret
            db.analyse_raw_gadgets(raw, &arch);

            // 'eax = edi' needs a rule-derived strategy, i.e. a second try
            nb += _assert(comp.max_tries == DEFAULT_MAX_TRIES, "ROPCompiler: wrong default max_tries");
            nb += _assert(comp.timeout_ms == 0, "ROPCompiler: there should be no timeout by default");
            ropchain = comp.compile("eax = edi");
            nb += _assert_ropchain(ropchain, "Couldn't find chain with the default max_tries");
            comp.max_tries = 1;
            ropchain = comp.compile("eax = edi");
            nb += _assert_no_ropchain(ropchain, "max_tries = 1 should only try the direct strategy");
            nb += _assert(!comp.last_compile_timed_out, "ROPCompiler: no timeout, should not report a time out");
            comp.max_tries = DEFAULT_MAX_TRIES;

            // A timeout that is not reached changes nothing, and "no chain" is not a time out
            comp.timeout_ms = 60000;
            ropchain = comp.compile("eax = edi");
            nb += _assert_ropchain(ropchain, "Couldn't find chain with a 60 s timeout");
            nb += _assert(!comp.last_compile_timed_out, "ROPCompiler: found a chain, should not report a time out");
            ropchain = comp.compile("eax = esi");
            nb += _assert_no_ropchain(ropchain, "Found a chain for an unsatisfiable query");
            nb += _assert(!comp.last_compile_timed_out, "ROPCompiler: search completed, should not report a time out");
            comp.timeout_ms = 0;

            // An expired deadline stops the gadget selection and the task loop
            query = "eax = edi";
            vector<ILInstruction> instr = comp.parse(query);
            comp.il_to_strategy(graphs, instr[0]);
            set_search_deadline(1);
            _wait_ms(5);
            // Let a check see it: the DFS only reads the clock every few hundred polls
            is_search_deadline_reached();
            nb += _assert(!graphs[0]->select_gadgets(db, nullptr, &arch), "Gadget selection ignored the search deadline");
            CompilerTask task(&arch);
            task.add_initial_strategy(graphs[0]);
            nb += _assert_no_ropchain(task.compile(&arch, &db), "CompilerTask ignored the search deadline");
            unset_search_deadline();
            graphs.clear();
            comp.il_to_strategy(graphs, instr[0]);
            task.clear();
            task.add_initial_strategy(graphs[0]);
            nb += _assert_ropchain(task.compile(&arch, &db), "CompilerTask: couldn't find chain without deadline");

            return nb;
        }

        // Gadget selection picks the first address without bad bytes, rejects a
        // gadget that has none without throwing, and then only needs the
        // constraint checks other than bad bytes
        unsigned int gadget_address_selection(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            Constraint constr;
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 0x0a0b0c0d)); // mov eax, ecx; ret
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 0x01020304)); // same gadget, second address
            raw.push_back(RawGadget(string("\x89\xD8\xC3", 3), 0x0102030a)); // mov eax, ebx; ret
            db.analyse_raw_gadgets(raw, &arch);
            Gadget* two_addrs = db.get_mov_reg(X86_EAX, X86_ECX).at(0);
            Gadget* one_addr = db.get_mov_reg(X86_EAX, X86_EBX).at(0);
            Node node(0, GadgetType::MOV_REG);
            const int addr_param = node.get_param_num_gadget_addr();
            constr.bad_bytes.add_bad_byte(0x0a);
            constr.mem_safety.add_safe_reg(X86_ESP); // As ROPCompiler::compile() does ('ret' reads [esp])

            nb += _assert(two_addrs->addresses.size() == 2, "Expected one gadget with two addresses");
            nb += _assert(node.assign_gadget(two_addrs, &arch, &constr), "assign_gadget() rejected a gadget with a valid address");
            nb += _assert(node.params[addr_param].value == 0x01020304, "assign_gadget() picked an address with bad bytes");
            nb += _assert(!node.assign_gadget(one_addr, &arch, &constr), "assign_gadget() accepted an address with bad bytes");
            nb += _assert(node.assign_gadget(one_addr, &arch, nullptr) && node.params[addr_param].value == 0x0102030a,
                "assign_gadget() without constraint should take the first address");

            // check() = bad bytes + check_except_bad_bytes()
            nb += _assert(!constr.check(one_addr, &arch) && constr.check_except_bad_bytes(one_addr, &arch),
                "check_except_bad_bytes() should ignore bad bytes only");
            nb += _assert(constr.check(two_addrs, &arch) && constr.check_except_bad_bytes(two_addrs, &arch),
                "Constraint checks rejected a valid gadget");
            constr.keep_regs.add_keep_reg(X86_EAX);
            nb += _assert(!constr.check(two_addrs, &arch) && !constr.check_except_bad_bytes(two_addrs, &arch),
                "check_except_bad_bytes() ignored keep_regs");
            return nb;
        }

        unsigned int direct_match(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;

            // Available gadgets
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 1)); // mov ecx, edi; mov ebx, 1; ret
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 2)); // mov eax, ecx; ret
            raw.push_back(RawGadget(string("\x89\xC3\xC3", 3), 3)); // mov ebx, eax; ret
            raw.push_back(RawGadget(string("\x01\xf0\x89\xc3\xc3", 5), 4)); // add eax, esp; mov ebx, eax; ret
            raw.push_back(RawGadget(string("\xbb\x04\x00\x00\x00\xc3", 6), 5)); // mov ebx, 4; ret
            raw.push_back(RawGadget(string("\x83\xc0\x04\x89\xc3\xc3", 6), 6)); // add eax, 4; mov ebx, eax; ret
            raw.push_back(RawGadget(string("\x8b\x59\xf7\x89\xd8\xc3", 6), 7)); // mov ebx, [ecx-9]; mov eax, ebx; ret
            raw.push_back(RawGadget(string("\x03\x39\xc3", 3), 8)); // add edi, [ecx]; ret
            raw.push_back(RawGadget(string("\xb9\x0a\x00\x00\x00\xc3", 6), 9)); // mov ecx, 10; ret
            raw.push_back(RawGadget(string("\x89\x0f\x89\x5e\xfd\xc3", 6), 10)); // mov [edi], ecx; mov [esi-3], ebx; ret
            raw.push_back(RawGadget(string("\xbe\x16\x00\x00\x00\xc3", 6), 11)); // mov esi, 22; ret
            raw.push_back(RawGadget(string("\xbf\x78\x56\x34\x12\xc3", 6), 12)); // mov edi, 0x12345678; ret
            raw.push_back(RawGadget(string("\x01\x21\xc3", 3), 13)); // add [ecx], esp; ret
            raw.push_back(RawGadget(string("\x33\x79\xf6\xc3", 4), 14)); // xor edi, [ecx-10]; ret
            raw.push_back(RawGadget(string("\x83\xc9\xff\xc3", 4), 15)); // or ecx, 0xffffffff; ret
            raw.push_back(RawGadget(string("\x21\x49\xf7\xc3", 4), 16)); // and [ecx-9], ecx; ret
            raw.push_back(RawGadget(string("\x01\x1E\xC3", 3), 17)); // add [esi], ebx; ret

            db.analyse_raw_gadgets(raw, &arch);

            // Test basic queries
            ropchain = comp.compile("eax = ecx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = 4");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = eax + 4");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = eax + esi ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = [ ecx - 0x9] ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = [ 1] ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [edi] = ecx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [ esi-   0x3] = ebx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [19] = ebx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [0x12345678] = ecx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" edi += [ecx]");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" edi ^= [0]");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [ecx+0x000 ] += esp  \t\t\n\t  ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ecx = -1");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [22] += 4");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");

            return nb;
        }

        unsigned int indirect_match(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            Constraint constr;
            constr.bad_bytes.add_bad_byte(0xff);

            // Available gadgets
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 1)); // mov ecx, edi; mov ebx, 1; ret
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 2)); // mov eax, ecx; ret
            raw.push_back(RawGadget(string("\x89\xC3\xC3", 3), 3)); // mov ebx, eax; ret
            raw.push_back(RawGadget(string("\xb9\xad\xde\x00\x00\xc3", 6), 4)); // mov ecx, 0xdead; ret
            raw.push_back(RawGadget(string("\x5f\x5e\x59\xc3", 4), 5)); // pop edi; pop esi; pop ecx; ret
            raw.push_back(RawGadget(string("\x89\xE8\xFF\xE6", 4), 6)); // mov eax, ebp; jmp esi
            raw.push_back(RawGadget(string("\x89\xF1\xFF\xE0", 4), 7)); // mov ecx, esi; jmp eax
            raw.push_back(RawGadget(string("\x5A\x59\xC3", 3), 8)); // pop edx; pop ecx; ret
            raw.push_back(RawGadget(string("\x8B\x40\x08\xC3", 4), 9)); // mov eax, [eax + 8]; ret
            raw.push_back(RawGadget(string("\x8D\x4B\x08\xC3", 4), 10)); // lea ecx, [ebx + 8]; ret
            raw.push_back(RawGadget(string("\x8D\x40\x20\xFF\xE1", 5), 11)); // lea eax, [eax + 32]; jmp ecx;
            raw.push_back(RawGadget(string("\x89\x43\x08\xC3", 4), 12)); // mov [ebx + 8], eax; ret

            db.analyse_raw_gadgets(raw, &arch);

            // Test mov_reg_transitivity
            ropchain = comp.compile("eax = edi");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile("ebx = edi");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");

            // Test mov_cst_transitivity
            ropchain = comp.compile("eax = 0xdead");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile("ebx = 0xdead");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            
            // Test mov_cst pop
            ropchain = comp.compile(" edi =   -2");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" eax = 0x12345678  ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            
            // Test generic adjust jmp
            ropchain = comp.compile(" ebx =  ebp");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" eax =  esi");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            
            // Test adjust load
            ropchain = comp.compile(" eax =  [ebx+16]");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" eax =  [eax+40]");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");

            // Test src transitivity
            ropchain = comp.compile(" [ebx+8] =  ebp");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            
            // Test adjust store
            ropchain = comp.compile(" [eax+8] =  ecx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");

            return nb;
        }
        
        unsigned int store_string(){
            unsigned int nb = 0;
            
            ArchX86 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            Constraint constr;
            constr.bad_bytes.add_bad_byte(0xff);

            // Available gadgets
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 1)); // mov ecx, edi; mov ebx, 1; ret
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 2)); // mov eax, ecx; ret
            raw.push_back(RawGadget(string("\x89\xC3\xC3", 3), 3)); // mov ebx, eax; ret
            raw.push_back(RawGadget(string("\xb9\xad\xde\x00\x00\xc3", 6), 4)); // mov ecx, 0xdead; ret
            raw.push_back(RawGadget(string("\x5f\x5e\x59\xc3", 4), 5)); // pop edi; pop esi; pop ecx; ret
            raw.push_back(RawGadget(string("\x89\xE8\xFF\xE6", 4), 6)); // mov eax, ebp; jmp esi
            raw.push_back(RawGadget(string("\x89\xF1\xFF\xE0", 4), 7)); // mov ecx, esi; jmp eax
            raw.push_back(RawGadget(string("\x5A\x59\xC3", 3), 8)); // pop edx; pop ecx; ret
            raw.push_back(RawGadget(string("\x8B\x40\x08\xC3", 4), 9)); // mov eax, [eax + 8]; ret
            raw.push_back(RawGadget(string("\x8D\x4B\x08\xC3", 4), 10)); // lea ecx, [ebx + 8]; ret
            raw.push_back(RawGadget(string("\x8D\x40\x20\xFF\xE1", 5), 11)); // lea eax, [eax + 32]; jmp ecx;
            raw.push_back(RawGadget(string("\x89\x43\x08\xC3", 4), 12)); // mov [ebx + 8], eax; ret

            db.analyse_raw_gadgets(raw, &arch);

            // Test adjust store
            ropchain = comp.compile(" [0x1234] =  'lala'");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            
            ropchain = comp.compile(" [0x1234] =  'lalatotoo\\x00'");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");

            return nb;
        }
        
        unsigned int incorrect_match(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            Constraint constr;
            constr.bad_bytes.add_bad_byte(0xff);

            // Test when adjust gadget clobbers reg that must be set
            // Here gadget 2 and 3 both modify ecx
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xF1\xFF\xE0", 4), 1)); // mov ecx, esi; jmp eax
            raw.push_back(RawGadget(string("\x59\xC3", 2), 2)); // pop ecx; ret
            raw.push_back(RawGadget(string("\x58\x59\xC3", 3), 3)); // pop eax; pop ecx; ret
            db.analyse_raw_gadgets(raw, &arch);
            ropchain = comp.compile(" ecx =  esi");
            nb += _assert_no_ropchain(ropchain, "Found ropchain but no ropchain should exist");
            
            // Test when adjust gadget clobbers input register
            // Here gadget 2 can set eax but modifies esi
            db.clear();
            raw.clear();
            raw.push_back(RawGadget(string("\x89\xF1\xFF\xE0", 4), 1)); // mov ecx, esi; jmp eax
            raw.push_back(RawGadget(string("\x5E\x58\xC3", 3), 2)); // pop esi; pop eax; ret
            raw.push_back(RawGadget(string("\xC3", 1), 3)); // ret
            db.analyse_raw_gadgets(raw, &arch);
            ropchain = comp.compile(" ecx =  esi");
            nb += _assert_no_ropchain(ropchain, "Found ropchain but no ropchain should exist");

            return nb;
        }
        
        unsigned int function_call_x86(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            Constraint constr;
            constr.bad_bytes.add_bad_byte(0xff);
            // Test when adjust gadget clobbers reg that must be set
            // Here gadget 2 and 3 both modify ecx
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x58\xFF\xE0", 3), 1)); // pop eax; jmp eax
            raw.push_back(RawGadget(string("\xC3", 1), 2)); // ret
            raw.push_back(RawGadget(string("\x59\xC3", 2), 3)); // pop ecx; ret
            raw.push_back(RawGadget(string("\x83\xC4\x0C\xC3", 4), 4)); // add esp, 12; ret
            db.analyse_raw_gadgets(raw, &arch);

            // X86 CDECL ABI
            ropchain = comp.compile(" 0x1234(42)", nullptr, ABI::X86_CDECL);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");

            ropchain = comp.compile(" 0x12345678(42, -1, 43)", nullptr, ABI::X86_CDECL);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");

            ropchain = comp.compile(" 0()", nullptr, ABI::X86_CDECL);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");
            
            // X86 STDCALL ABI
            ropchain = comp.compile(" 0x1234(42)", nullptr, ABI::X86_STDCALL);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");

            ropchain = comp.compile(" 0x12345678(42, -1, 43)", nullptr, ABI::X86_STDCALL);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");

            ropchain = comp.compile(" 0()", nullptr, ABI::X86_STDCALL);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");
            
            return nb;
        }

        unsigned int function_call_x64(){
            unsigned int nb = 0;
            ArchX64 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            Constraint constr;
            constr.bad_bytes.add_bad_byte(0xff);
            // Test when adjust gadget clobbers reg that must be set
            // Here gadget 2 and 3 both modify ecx
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x58\xFF\xE0", 3), 1)); // pop rax; jmp rax
            raw.push_back(RawGadget(string("\xC3", 1), 2)); // ret
            raw.push_back(RawGadget(string("\x5F\xC3", 2), 3)); // pop rdi; ret
            raw.push_back(RawGadget(string("\x48\x83\xC4\x08\xC3", 5), 4)); // add rsp, 8; ret
            raw.push_back(RawGadget(string("\x5E\xC3", 2), 5)); // pop rsi; ret
            raw.push_back(RawGadget(string("\x5A\xC3", 2), 6)); // pop rdx; ret
            raw.push_back(RawGadget(string("\x59\xC3", 2), 7)); // pop rcx; ret
            raw.push_back(RawGadget(string("\x41\x58\xc3", 3), 8)); // pop r8; ret
            raw.push_back(RawGadget(string("\x41\x59\x59\xc3", 4), 9)); // pop r9; pop rcx; ret
            raw.push_back(RawGadget(string("\x48\x89\xef\xc3",4), 10)); // mov rdi, rbp; ret
            raw.push_back(RawGadget(string("\x48\x83\xC4\x18\xC3", 5), 11)); // add rsp, 24; ret
            raw.push_back(RawGadget(string("\x49\x89\xd1\xc3",4), 12)); // mov r9, rdx; ret
            raw.push_back(RawGadget(string("\x48\x83\xC4\x10\xC3", 5), 13)); // add rsp, 16; ret
            db.analyse_raw_gadgets(raw, &arch);

            // X64 SYSTEM V
            ropchain = comp.compile(" 0x1234(42)", nullptr, ABI::X64_SYSTEM_V);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");
            
            ropchain = comp.compile(" 0x1234(1, 2, 3, 4)", nullptr, ABI::X64_SYSTEM_V);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");
            
            ropchain = comp.compile(" 0x1234(rbp, 2, 3, 4, 5, 6)", nullptr, ABI::X64_SYSTEM_V);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");
            
            ropchain = comp.compile(" 0x1234(rbp, 2, 3, 4, 5, 6, 7, 8)", nullptr, ABI::X64_SYSTEM_V);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");
            
            ropchain = comp.compile(" 0x1234(rbp, 2, 3, 4, 5, 6, 7, 8, 9)", nullptr, ABI::X64_SYSTEM_V);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");

            // X64 Microsoft
            ropchain = comp.compile(" 0x1234(42)", nullptr, ABI::X64_MS);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");
            
            ropchain = comp.compile(" 0x1234(1, 2, 3, rdx)", nullptr, ABI::X64_MS);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");
            
            ropchain = comp.compile(" 0x1234(1, 2, 3, 4, 5, 6)", nullptr, ABI::X64_MS);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");
            
            ropchain = comp.compile(" 0x1234(1, 2, 3, rdx, 5, 6, 7)", nullptr, ABI::X64_MS);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to call function");

            return nb;
        }

        unsigned int syscall_x86(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            Constraint constr;
            constr.bad_bytes.add_bad_byte(0xff);
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x58\xC3", 2), 1)); // pop eax; ret
            raw.push_back(RawGadget(string("\x5B\xC3", 2), 2)); // pop ebx; ret
            raw.push_back(RawGadget(string("\x83\xC5\x20\x0F\x34", 5), 3)); // add ebp, 32; sysenter
            raw.push_back(RawGadget(string("\x59\xC3", 2), 4)); // pop ecx; ret
            raw.push_back(RawGadget(string("\x59\x5A\xC3", 3), 5)); // pop ecx; pop edx; ret
            raw.push_back(RawGadget(string("\x58\x89\xC6\xC3", 4), 6)); // pop eax; mov esi, eax; ret
            raw.push_back(RawGadget(string("\x89\xDA\xC3", 3), 7)); // mov edx, ebx; ret
            db.analyse_raw_gadgets(raw, &arch);

            // X86 Linux
            ropchain = comp.compile(" sys_exit(1)", nullptr, ABI::NONE, System::LINUX);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to make syscall");

            ropchain = comp.compile(" sys_execve( 3, 2, 1)", nullptr, ABI::NONE, System::LINUX);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to make syscall");

            ropchain = comp.compile(" sys_execve( 3, 2, ebx)", nullptr, ABI::NONE, System::LINUX);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to make syscall");

            ropchain = comp.compile(" sys_ptrace( 3, 2, 1, 2)", nullptr, ABI::NONE, System::LINUX);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to make syscall");

            ropchain = comp.compile("  sys_123(1, 2, 3) ", nullptr, ABI::NONE, System::LINUX);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to make syscall");

            return nb;
        }
        
        unsigned int syscall_x64(){
            unsigned int nb = 0;
            ArchX64 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            Constraint constr;
            constr.bad_bytes.add_bad_byte(0xff);
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x58\xC3", 2), 1)); // pop rax; ret
            raw.push_back(RawGadget(string("\x5F\xC3", 2), 2)); // pop rdi; ret
            raw.push_back(RawGadget(string("\x83\xC5\x20\x0F\x05", 5), 3)); // add ebp, 32; syscall
            raw.push_back(RawGadget(string("\x5E\xC3", 2), 4)); // pop rsi; ret
            raw.push_back(RawGadget(string("\x59\x5A\xC3", 3), 5)); // pop rcx; pop rdx; ret
            raw.push_back(RawGadget(string("\x58\x48\x89\xC6\xC3", 5), 6)); // pop rax; mov rsi, rax; ret
            raw.push_back(RawGadget(string("\x48\x89\xF2\xC3", 4), 7)); // mov rdx, rsi; ret
            db.analyse_raw_gadgets(raw, &arch);

            // X64 Linux
            ropchain = comp.compile(" sys_exit(1)", nullptr, ABI::NONE, System::LINUX);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to make syscall");
            
            ropchain = comp.compile(" sys_execve(1, 2, 3)", nullptr, ABI::NONE, System::LINUX);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to make syscall");
            
            ropchain = comp.compile(" sys_execve(1, 2, rsi)", nullptr, ABI::NONE, System::LINUX);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to make syscall");

            ropchain = comp.compile(" sys_0x42(1, 2, rsi)", nullptr, ABI::NONE, System::LINUX);
            nb += _assert_ropchain(ropchain, "Couldn't build ropchain to make syscall");

            return nb;
        }
        
    }
}

using namespace test::compiler; 
// All unit tests 
void test_compiler(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing ROP compiler... " << std::flush;
    total += strategy_queue_order();
    total += strategy_queue_equivalence();
    total += search_deadline();
    total += search_limits();
    total += gadget_address_selection();
    total += direct_match();
    total += indirect_match();
    total += function_call_x86();
    total += function_call_x64();
    total += syscall_x86();
    total += syscall_x64();
    total += store_string();
    total += incorrect_match();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
