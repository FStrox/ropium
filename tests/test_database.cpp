#include "database.hpp"
#include "exception.hpp"
#include <string>
#include <sstream>
#include <tuple>
#include <iostream>
#include <iomanip>
#include <algorithm>

using std::cout;
using std::endl; 
using std::string;
using std::make_tuple;
using std::tuple;

namespace test{
    namespace database{
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int base_db(){
            BaseDB<tuple<int, int>> db;
            int nb = 0;
            Gadget *g1 = new Gadget(), *g2 = new Gadget();
            vector<Gadget*> all;
            g1->id = 0; g2->id = 1;
            all.push_back(g1);
            all.push_back(g2);
            
            db.add(make_tuple(1,2), g1);
            nb += _assert(db.get(make_tuple(1,2))[0] == g1, "BaseDB, failed to add then get gadget");
            db.add(make_tuple(1,4456), g2);
            nb += _assert(db.get(make_tuple(1,4456))[0] == g2, "BaseDB, failed to add then get gadget");

            delete g1; delete g2;
            return nb; 
        }
        
        unsigned int _assert_db(addr_t addr, const vector<Gadget*>& list){
            for( Gadget* g : list ){
                if( std::find(g->addresses.begin(), g->addresses.end(), addr) != g->addresses.end() )
                    return 1;
            }
            cout << "\nFail: " << "GadgetDB: failed to classify/return gadget correctly" << endl << std::flush; 
                throw test_exception();
        }
        
        unsigned int classification(){
            unsigned int nb = 0;
            Arch* arch = new ArchX86();
            GadgetDB db;

            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\xb8\x03\x00\x00\x00\xc3", 6), 0)); // mov eax, 3; ret
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 1)); // mov ecx, edi; mov ebx, 1; ret
            raw.push_back(RawGadget(string("\xb8\x03\x00\x00\x00\xc3", 6), 2)); // mov eax, 3; ret
            raw.push_back(RawGadget(string("\x83\xc0\x02\x89\xc6\xc3", 6), 3)); // add eax, 2; mov esi, eax; ret
            raw.push_back(RawGadget(string("\x81\xea\x34\x12\x00\x00\xc3", 7), 4)); // sub edx, 0x1234; ret
            raw.push_back(RawGadget(string("\x01\xe5\xc3", 3), 5)); // add ebp, esp; ret
            raw.push_back(RawGadget(string("\x58\x5e\xc3", 3), 6)); // pop eax; pop esi; ret
            raw.push_back(RawGadget(string("\x8b\x59\xf7\x89\xd8\xc3", 6), 7)); // mov ebx, [ecx-9]; mov eax, ebx; ret
            raw.push_back(RawGadget(string("\x03\x39\xc3", 3), 8)); // add edi, [ecx]; ret
            raw.push_back(RawGadget(string("\x33\x79\xf6\xc3", 4), 9)); // xor edi, [ecx-10]; ret
            raw.push_back(RawGadget(string("\xff\xe0", 2), 10)); // jmp eax;
            raw.push_back(RawGadget(string("\x89\x0f\x89\x5e\xfd\xc3", 6), 11)); // mov [edi], ecx; mov [esi-3], ebx; ret
            raw.push_back(RawGadget(string("\x01\x21\xc3", 3), 12)); // add [ecx], esp; ret
            raw.push_back(RawGadget(string("\x21\x49\xf7\xc3", 4), 13)); // and [ecx-9], ecx; ret
            raw.push_back(RawGadget(string("\x83\xC0\x03\xCD\x80", 5), 14)); // add eax, 3; int 0x80
            raw.push_back(RawGadget(string("\x83\xC5\x20\x0F\x34", 5), 15)); // add ebp, 32; sysenter

            db.analyse_raw_gadgets(raw, arch);

            // Test gadget classification
            nb += _assert_db(0, db.get_mov_cst(X86_EAX, 3));
            nb += _assert_db(1, db.get_mov_cst(X86_EBX, 1));
            nb += _assert_db(1, db.get_mov_reg(X86_ECX, X86_EDI));
            nb += _assert_db(2, db.get_mov_cst(X86_EAX, 3));
            nb += _assert_db(3, db.get_amov_cst(X86_EAX, X86_EAX, Op::ADD, 2));
            nb += _assert_db(3, db.get_amov_cst(X86_ESI, X86_EAX, Op::ADD, 2));
            nb += _assert_db(4, db.get_amov_cst(X86_EDX, X86_EDX, Op::ADD, -0x1234));
            nb += _assert_db(5, db.get_amov_reg(X86_EBP, X86_ESP, Op::ADD, X86_EBP));
            nb += _assert_db(6, db.get_load(X86_EAX, X86_ESP, 0));
            nb += _assert_db(6, db.get_load(X86_ESI, X86_ESP, 4));
            nb += _assert_db(7, db.get_load(X86_EBX, X86_ECX, -9));
            nb += _assert_db(7, db.get_load(X86_EAX, X86_ECX, -9));
            nb += _assert_db(8, db.get_aload(X86_EDI, Op::ADD, X86_ECX, 0));
            nb += _assert_db(9, db.get_aload(X86_EDI, Op::XOR, X86_ECX, -10));
            nb += _assert_db(10, db.get_jmp(X86_EAX));
            nb += _assert_db(10, db.get_mov_reg(X86_EIP, X86_EAX));
            nb += _assert_db(11, db.get_store(X86_EDI, 0, X86_ECX));
            nb += _assert_db(11, db.get_store(X86_ESI, -3, X86_EBX));
            nb += _assert_db(12, db.get_astore(X86_ECX, 0, Op::ADD, X86_ESP));
            nb += _assert_db(13, db.get_astore(X86_ECX, -9, Op::AND, X86_ECX));
            nb += _assert_db(14, db.get_int80());
            nb += _assert_db(15, db.get_syscall());

            delete arch;
            return nb;
        }
        
        unsigned int classification_x64(){
            unsigned int nb = 0;
            Arch* arch = new ArchX64();
            GadgetDB db;

            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x83\xC5\x20\x0F\x05", 5), 1)); // add ebp, 32; syscall

            db.analyse_raw_gadgets(raw, arch);

            // Test gadget classification
            nb += _assert_db(1, db.get_syscall());

            delete arch;
            return nb;
        }

        // clear() deletes the gadgets, so it must empty every table: a table it
        // forgets keeps dangling pointers that the next add() or lookup reads
        unsigned int clear_db(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\xb8\x03\x00\x00\x00\xc3", 6), 0)); // mov eax, 3; ret
            raw.push_back(RawGadget(string("\xff\xe0", 2), 1)); // jmp eax
            raw.push_back(RawGadget(string("\x83\xC0\x03\xCD\x80", 5), 2)); // add eax, 3; int 0x80
            raw.push_back(RawGadget(string("\x83\xC5\x20\x0F\x34", 5), 3)); // add ebp, 32; sysenter

            for( int round = 0; round < 2; round++ ){
                db.analyse_raw_gadgets(raw, &arch);
                nb += _assert(db.get_mov_cst(X86_EAX, 3).size() == 1, "GadgetDB: expected one mov_cst gadget");
                nb += _assert(db.get_jmp(X86_EAX).size() == 1, "GadgetDB: expected one jmp gadget");
                nb += _assert(db.get_int80().size() == 1, "GadgetDB: expected one int80 gadget");
                nb += _assert(db.get_syscall().size() == 1, "GadgetDB: expected one syscall gadget");
                db.clear();
                nb += _assert(db.get_mov_cst(X86_EAX, 3).empty(), "GadgetDB::clear() left mov_cst gadgets");
                nb += _assert(db.get_jmp(X86_EAX).empty(), "GadgetDB::clear() left jmp gadgets");
                nb += _assert(db.get_int80().empty(), "GadgetDB::clear() left int80 gadgets");
                nb += _assert(db.get_syscall().empty(), "GadgetDB::clear() left syscall gadgets");
            }
            return nb;
        }

        // A lookup miss must leave the table as it is: the gadget selection
        // does millions of them, and a growing table rehashes, which changes
        // the order of equal-size gadgets in get_possible() results
        unsigned int lookup_miss_db(){
            unsigned int nb = 0;
            BaseDB<tuple<int, int>> db;
            vector<Gadget*> gadgets;
            for( int i = 0; i < 20; i++ ){
                gadgets.push_back(new Gadget());
                gadgets.back()->id = i;
                // Same size: get_possible() keeps the table order between them
                gadgets.back()->nb_instr = 1;
                gadgets.back()->nb_instr_ir = 1;
                db.add(make_tuple(i % 4, i), gadgets.back());
            }
            bool free_src[2] = {false, true};
            PossibleGadgets* before = db.get_possible(make_tuple(1, 0), free_src, 2);
            size_t size = db.db.size(), buckets = db.db.bucket_count();

            for( int i = 0; i < 1000; i++ ){
                nb += _assert(db.get(make_tuple(100 + i, i)).empty(), "BaseDB: lookup of a missing key returned gadgets");
            }
            nb += _assert(db.get(make_tuple(1, 5))[0] == gadgets[5], "BaseDB: failed to get a gadget after lookup misses");
            nb += _assert(db.db.size() == size, "BaseDB: a lookup miss added a key");
            nb += _assert(db.db.bucket_count() == buckets, "BaseDB: lookup misses rehashed the table");

            PossibleGadgets* after = db.get_possible(make_tuple(1, 0), free_src, 2);
            nb += _assert(before->gadgets.size() == 5 && after->gadgets.size() == before->gadgets.size(),
                          "BaseDB: wrong get_possible() result size");
            for( int i = 0; i < before->gadgets.size(); i++ ){
                nb += _assert(after->gadgets[i].first == before->gadgets[i].first &&
                              after->gadgets[i].second == before->gadgets[i].second,
                              "BaseDB: get_possible() order changed after lookup misses");
            }
            delete before;
            delete after;
            for( Gadget* g : gadgets )
                delete g;
            return nb;
        }

        // Reference for has_possible_*(): does get_possible_*() return a
        // gadget with the right branch type?
        bool _possible_has_branch(std::shared_ptr<const PossibleGadgets> possible, BranchType branch){
            bool res = false;
            for( auto& pos : possible->gadgets )
                for( Gadget* g : *(pos.second) )
                    res = res || branch == BranchType::ANY || g->branch_type == branch;
            return res;
        }

        bool _same_possible(const PossibleGadgets& p1, const PossibleGadgets& p2){
            if( p1.gadgets.size() != p2.gadgets.size() )
                return false;
            for( int i = 0; i < p1.gadgets.size(); i++ )
                if( p1.gadgets[i].first != p2.gadgets[i].first || p1.gadgets[i].second != p2.gadgets[i].second )
                    return false;
            return true;
        }

        // get_possible_*() results are cached: they must equal the uncached
        // result, not depend on the values of free params, and follow add()
        unsigned int possible_cache_db(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 0)); // mov ecx, edi; mov ebx, 1; ret
            raw.push_back(RawGadget(string("\x89\xC3\xC3", 3), 1)); // mov ebx, eax; ret
            raw.push_back(RawGadget(string("\x89\xCB\xC3", 3), 2)); // mov ebx, ecx; ret
            raw.push_back(RawGadget(string("\x89\xF5\xFF\xE0", 4), 3)); // mov ebp, esi; jmp eax
            raw.push_back(RawGadget(string("\x8b\x59\xf7\x89\xd8\xc3", 6), 4)); // mov ebx, [ecx-9]; mov eax, ebx; ret
            db.analyse_raw_gadgets(raw, &arch);

            bool is_free[2];
            for( int mask = 0; mask < 4; mask++ ){
                is_free[0] = mask & 1;
                is_free[1] = mask & 2;
                for( reg_t r1 = X86_EAX; r1 <= X86_EIP; r1++ ){
                    for( reg_t r2 = X86_EAX; r2 <= X86_EIP; r2++ ){
                        PossibleGadgets* uncached = db.mov_reg.get_possible(make_tuple(r1, r2), is_free, 2);
                        std::shared_ptr<const PossibleGadgets> cached = db.get_possible_mov_reg(r1, r2, is_free);
                        nb += _assert(_same_possible(*cached, *uncached), "GadgetDB: cached get_possible_mov_reg() differs");
                        nb += _assert(db.get_possible_mov_reg(r1, r2, is_free) == cached, "GadgetDB: get_possible_mov_reg() not cached");
                        delete uncached;
                    }
                }
            }
            // Values of free params are not part of the query
            bool src_free[2] = {false, true};
            std::shared_ptr<const PossibleGadgets> ebx_x = db.get_possible_mov_reg(X86_EBX, X86_EAX, src_free);
            nb += _assert(db.get_possible_mov_reg(X86_EBX, X86_ESI, src_free) == ebx_x, "GadgetDB: free param value changed the query");
            nb += _assert(ebx_x->gadgets.size() == 2, "GadgetDB: expected mov ebx, eax and mov ebx, ecx");

            // add() empties the cache; results already handed out stay valid
            raw.clear();
            raw.push_back(RawGadget(string("\x89\xD3\xC3", 3), 5)); // mov ebx, edx; ret
            db.analyse_raw_gadgets(raw, &arch);
            nb += _assert(db.mov_reg.possible_cache_size() == 0, "GadgetDB: add() kept cached queries");
            nb += _assert(db.get_possible_mov_reg(X86_EBX, X86_EAX, src_free)->gadgets.size() == 3, "GadgetDB: stale cached query after add()");
            nb += _assert(ebx_x->gadgets.size() == 2 && ebx_x->gadgets[0].second->size() == 1, "GadgetDB: handed out result changed");

            // The cache is bounded
            bool dst_free[3] = {true, false, false};
            // eax and ebx <- mem(ecx - 9)
            std::shared_ptr<const PossibleGadgets> first = db.get_possible_load(X86_EAX, X86_ECX, -9, dst_free);
            nb += _assert(first->gadgets.size() == 2, "GadgetDB: expected two loads from ecx - 9");
            for( cst_t offset = 0; offset < 5000; offset++ ){
                db.get_possible_load(X86_EAX, X86_ECX, offset, dst_free);
                nb += _assert(db.load.possible_cache_size() <= BaseDB<tuple<reg_t, reg_t, addr_t>>::POSSIBLE_CACHE_MAX,
                              "GadgetDB: get_possible cache grew past its limit");
            }
            nb += _assert(first->gadgets.size() == 2, "GadgetDB: a result was freed while still used");
            db.clear();
            nb += _assert(db.mov_reg.possible_cache_size() == 0 && db.load.possible_cache_size() == 0, "GadgetDB: clear() kept cached queries");
            return nb;
        }

        unsigned int has_possible_db(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 0)); // mov ecx, edi; mov ebx, 1; ret
            raw.push_back(RawGadget(string("\x89\xC3\xC3", 3), 1)); // mov ebx, eax; ret
            raw.push_back(RawGadget(string("\x89\xF5\xFF\xE0", 4), 2)); // mov ebp, esi; jmp eax
            raw.push_back(RawGadget(string("\x8b\x59\xf7\x89\xd8\xc3", 6), 3)); // mov ebx, [ecx-9]; mov eax, ebx; ret
            raw.push_back(RawGadget(string("\x8B\x4F\x04\xFF\xE0", 5), 4)); // mov ecx, [edi+4]; jmp eax
            raw.push_back(RawGadget(string("\x58\x5e\xc3", 3), 5)); // pop eax; pop esi; ret
            db.analyse_raw_gadgets(raw, &arch);
            size_t mov_reg_keys = db.mov_reg.db.size(), load_keys = db.load.db.size();

            BranchType branches[] = {BranchType::ANY, BranchType::RET, BranchType::JMP};
            cst_t offsets[] = {-9, 0, 4, 8};
            bool is_free[3];
            for( BranchType branch : branches ){
                for( int mask = 0; mask < 8; mask++ ){
                    for( int p = 0; p < 3; p++ )
                        is_free[p] = mask & (1 << p);
                    for( reg_t r1 = X86_EAX; r1 <= X86_EIP; r1++ ){
                        for( reg_t r2 = X86_EAX; r2 <= X86_EIP; r2++ ){
                            if( mask < 4 ){
                                nb += _assert(db.has_possible_mov_reg(r1, r2, is_free, branch) ==
                                              _possible_has_branch(db.get_possible_mov_reg(r1, r2, is_free), branch),
                                              "GadgetDB: has_possible_mov_reg() disagrees with get_possible_mov_reg()");
                            }
                            for( cst_t offset : offsets ){
                                nb += _assert(db.has_possible_load(r1, r2, offset, is_free, branch) ==
                                              _possible_has_branch(db.get_possible_load(r1, r2, offset, is_free), branch),
                                              "GadgetDB: has_possible_load() disagrees with get_possible_load()");
                            }
                        }
                    }
                }
            }
            // A few known answers, so that both functions can't be wrong the same way
            bool src_free[2] = {false, true}, dst_free[2] = {true, false};
            nb += _assert(db.has_possible_mov_reg(X86_EBX, X86_EAX, src_free, BranchType::RET), "GadgetDB: missed mov ebx, X");
            nb += _assert(!db.has_possible_mov_reg(X86_EDX, X86_EAX, src_free, BranchType::ANY), "GadgetDB: found mov edx, X");
            nb += _assert(db.has_possible_mov_reg(X86_EBP, X86_ESI, dst_free, BranchType::JMP), "GadgetDB: missed mov X, esi; jmp");
            nb += _assert(!db.has_possible_mov_reg(X86_EBP, X86_ESI, dst_free, BranchType::RET), "GadgetDB: found mov X, esi; ret");
            nb += _assert(db.mov_reg.db.size() == mov_reg_keys && db.load.db.size() == load_keys,
                          "GadgetDB: has_possible_*() or get_possible_*() added keys");
            return nb;
        }

    }
}

using namespace test::database;
// All unit tests 
void test_database(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing gadget database... " << std::flush;  
    total += base_db();
    total += classification();
    total += classification_x64();
    total += clear_db();
    total += lookup_miss_db();
    total += has_possible_db();
    total += possible_cache_db();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
