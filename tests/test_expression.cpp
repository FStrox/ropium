#include "expression.hpp"
#include "simplification.hpp"
#include "exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <set>
#include <iomanip>

using std::cout;
using std::endl; 
using std::string;

namespace test{
    namespace expression{
        // Individual unit tests
        unsigned int basic(){
            Expr e1, e2, e3, e4, e5, e6, e7, e8; 
            for( int i = 0; i < 10; i++){
                e1 = exprcst(32, -1);
                e2 = exprcst(32, 1048567);
                e3 = exprmem(32, e2);
                e4 = -e1;
                e5 = e2 - e1;
                e6 = extract(e1, 31, 23);
                e7 = e6;
            }
            return 0;
        }

        /* Expression hashing */
        unsigned int _assert_hash_eq(Expr e1, Expr e2){
            if( e1->hash() != e2->hash() ){
                cout << endl << "Fail: _assert_hash_eq: " << e1 << " == " << e2 << endl;
                throw test_exception();  
            }
            return 1; 
        }
        
        unsigned int _assert_hash_neq(Expr e1, Expr e2){
            if( e1->hash() == e2->hash() ){
                cout << endl << "Fail: _assert_hash_eq: " << e1 << " == " << e2 << endl;
                throw test_exception();  
            }
            return 1; 
        }
        unsigned hashing(){
            Expr    e1 = exprcst(32,1),
                    e2 = exprvar(32, "var1"),
                    e3 = exprmem(32, e2),
                    e4 = -e1,
                    e5 = e2 & e3,
                    e6 = exprmem(32, e5),
                    e7 = exprmem(32, e6),
                    e8 = bisz(32, e5, 1),
                    e9 = e3 % e5;;
            unsigned int nb = 0;
            // Hash equality 
            nb += _assert_hash_eq(e1, exprcst(32,1));
            nb += _assert_hash_eq(e2, exprvar(32, "var1"));
            nb += _assert_hash_eq(e3, exprmem(32, e2));
            nb += _assert_hash_eq(e4, (-e1));
            nb += _assert_hash_eq(e5, (e2 & e3));
            nb += _assert_hash_eq(e6, exprmem(32, e5));
            nb += _assert_hash_eq(e7, exprmem(32,e6));
            nb += _assert_hash_eq(e8, bisz(32, e5, 1));
            nb += _assert_hash_eq(e9, e3%e5);
            // Hash inequality
            nb += _assert_hash_neq(e1, e2);
            nb += _assert_hash_neq(e2,e3);
            nb += _assert_hash_neq(e3,e4);
            nb += _assert_hash_neq(e4,e5);
            nb += _assert_hash_neq(e5,e6);
            nb += _assert_hash_neq(e6,e7);
            nb += _assert_hash_neq(e8, bisz(32, e5, 0));
            nb += _assert_hash_neq(e9, e5%e3);
            return nb;
        }
        
        /* Expression Canonization */
        unsigned int _assert_canonize_eq(Expr e1, Expr e2 ){
            Expr tmp1 = expr_canonize(e1), tmp2 = expr_canonize(e2);
            if(!(tmp1->eq(tmp2))){
                cout << endl << "Fail:  _assert_canonize_eq: " << e1 << " <==> " << e2 << endl
                << "Note: canonized as : " << tmp1 << " <==> " << tmp2 << endl << std::flush;
                throw test_exception(); 
            }
            return 1;
        }
        unsigned int _assert_canonize_neq(Expr e1, Expr e2 ){
            Expr tmp1 = expr_canonize(e1), tmp2 = expr_canonize(e2);
            if(!tmp1->neq(tmp2)){
                cout << endl << "Fail:  _assert_canonize_neq: " << e1 << " <=/=> " << e2 << endl
                << "Note: canonized as : " << tmp1 << " <==> " << tmp2 << endl << std::flush;
                throw test_exception(); 
            }
            return 1;
        }
        unsigned int canonize(){
            Expr    cst1 = exprcst(32, 1),
                    cst2 = exprcst(32, 567),
                    var1 = exprvar(32, "var1"),
                    var2 = exprvar(32, "var2"),
                    var3 = exprvar(32, "var3"),
                    un1 = -var2,
                    bin1 = var1+var2,
                    bin2 = var3/var2,
                    bin3 = sdiv(var3,var2); 
            unsigned int nb = 0;
            // a+b == b+a 
            nb += _assert_canonize_eq((cst1+cst2), (cst2+cst1));
            nb += _assert_canonize_eq((cst1+var1), (var1+cst1));
            nb += _assert_canonize_eq((bin3+var1), (var1+bin3));
            nb += _assert_canonize_eq((bin1+bin2), (bin2+bin1));
            nb += _assert_canonize_eq((bin1+bin1), (bin1+bin1)); 
            // a*b == b*a
            nb += _assert_canonize_eq((cst1*cst2), (cst2*cst1));
            nb += _assert_canonize_eq((cst1*var1), (var1*cst1));
            // (a^b)^c == (c^b)^a
            nb += _assert_canonize_eq( cst1^var1^bin3, cst1^bin3^var1);
            // a/b/c == a/c/b
            nb += _assert_canonize_eq( var2/var3/un1, var2/un1/var3);
            // a/b != b/a 
            nb += _assert_canonize_neq(var3/cst1, cst1/var3);
            // a<<b != b<<a
            nb += _assert_canonize_neq(shl(bin1,bin2), shl(bin2, bin1));
            // a-b-c == a-c-b
            nb += _assert_canonize_eq(cst1-var1-bin3, cst1-bin3-var1);
            // a-b != b-a
            nb += _assert_canonize_neq(cst2-un1, un1-cst2);
            // Concat reordering
            nb += _assert_canonize_eq(concat(var1, concat(var2, var3)), concat(concat(var1, var2), var3));
            return nb;  
        };
        

        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }

        /* Concretization */
        unsigned int concretization(){
            unsigned int nb = 0; 
            VarContext ctx;
            VarContext ctx2;
            Expr    v1 = exprvar(32, "var1" ),
                    v2 = exprvar(32, "var2"),
                    v3 = exprvar(64, "var3"),
                    v4 = exprvar(64, "var4"),
                    e1 = v1|v2, 
                    e2 = v3+v4,
                    e3 = extract(v1, 8, 1),
                    e4 = concat(v2,v1); 
            ctx.set("var1", 10);
            ctx.set("var2", -2);
            ctx.set("var3", 0xffff000000000000);
            ctx.set("var4", 0x0000ffffffffffff);
            
            ctx2.set("var1", 7);
            ctx2.set("var2", -1);
            ctx2.set("var3", 0xeeee000000000000);
            ctx2.set("var4", 0x0000eeeeeeeeeeee);
            
            nb += _assert( v1->concretize(&ctx) == 10, "Concretization gave wrong result");
            nb += _assert( v2->concretize(&ctx) == -2, "Concretization gave wrong result"); 
            nb += _assert( v3->concretize(&ctx) == 0xffff000000000000, "Concretization gave wrong result"); 
            nb += _assert( v4->concretize(&ctx) == 0x0000ffffffffffff, "Concretization gave wrong result"); 
            
            nb += _assert( (v1+v2)->concretize(&ctx) == exprcst(32, 8)->concretize(&ctx), "Concretization gave wrong result"); 
            nb += _assert( (v1*v2)->concretize(&ctx) == exprcst(32, -20)->concretize(&ctx), "Concretization gave wrong result"); 
            nb += _assert( (v1/v2)->concretize(&ctx) == exprcst(32, 0)->concretize(&ctx), "Concretization gave wrong result"); 
            nb += _assert( sdiv(v1,v2)->concretize(&ctx) == exprcst(32, -5)->concretize(&ctx), "Concretization gave wrong result"); 
            nb += _assert( (v1^v2)->concretize(&ctx) == exprcst(32, 10^-2)->concretize(&ctx), "Concretization gave wrong result");
            nb += _assert( (v1|v2)->concretize(&ctx) == exprcst(32, 10|-2)->concretize(&ctx), "Concretization gave wrong result");
            nb += _assert( extract(v2,31,24)->concretize(&ctx) == exprcst(8, 0xff)->concretize(&ctx), "Concretization gave wrong result");
            nb += _assert( shr(v1,exprcst(32, 2))->concretize(&ctx) == 2, "Concretization gave wrong result");
            nb += _assert( shl(exprcst(32, 0x800000001),exprcst(32, 2))->concretize(&ctx) == 4, "Concretization gave wrong result");
            nb += _assert( concat(v1,v2)->concretize(&ctx) == 0x0000000afffffffe, "Concretization gave wrong result");
            nb += _assert( bisz(16, v1, 1)->concretize(&ctx) == 0, "Concretization gave wrong result");
            nb += _assert( bisz(16, v1, 0)->concretize(&ctx) == 1, "Concretization gave wrong result");
            nb += _assert( bisz(4, exprcst(26, 0), 1)->concretize(&ctx) == 1, "Concretization gave wrong result");
            nb += _assert( bisz(4, exprcst(26, 0), 0)->concretize(&ctx) == 0, "Concretization gave wrong result");
            
            nb += _assert( smod(exprcst(32, -6), exprcst(32, 5))->concretize(&ctx) == -1, "Concretization gave wrong result");
            nb += _assert( smod(exprcst(32, -10), exprcst(32,3))->concretize(&ctx) == -1, "Concretization gave wrong result");
            nb += _assert( smod(exprcst(32, 10), exprcst(32,-3))->concretize(&ctx) == 1, "Concretization gave wrong result");
            
            // multiplications
            nb += _assert( mulh(exprcst(64, 0xbbf543), exprcst(64, 0xfffffabc7865))->concretize(&ctx) == 0xbb, "Concretization gave wrong result");
            nb += _assert( mulh(exprcst(32, 0xbbf543), exprcst(32, 0xc7865))->concretize(&ctx) == 0x927, "Concretization gave wrong result");
            nb += _assert( smull(exprcst(8, 48), exprcst(8, 4))->concretize(&ctx) == 0xffffffffffffffc0, "Concretization gave wrong result");
            nb += _assert( smulh(exprcst(8, 48), exprcst(8, 4))->concretize(&ctx) == 0, "Concretization gave wrong result");
            nb += _assert( smull(exprcst(8, -4), exprcst(8, 4))->concretize(&ctx) == 0xfffffffffffffff0, "Concretization gave wrong result");
            nb += _assert( smulh(exprcst(8, -4), exprcst(8, 4))->concretize(&ctx) == 0xffffffffffffffff, "Concretization gave wrong result");
            nb += _assert( smull(exprcst(16, 48), exprcst(16, 4))->concretize(&ctx) == 0xc0, "Concretization gave wrong result");
            nb += _assert( smulh(exprcst(16, 48), exprcst(16, 4))->concretize(&ctx) == 0, "Concretization gave wrong result");
            nb += _assert( smull(exprcst(32, 4823424), exprcst(32, -423))->concretize(&ctx) == 0xffffffff86635D80, "Concretization gave wrong result");
            nb += _assert( smulh(exprcst(32, 4823424), exprcst(32, -423))->concretize(&ctx) == 0xffffffffffffffff, "Concretization gave wrong result");
            nb += _assert( smull(exprcst(32, -1), exprcst(32, -1))->concretize(&ctx) == 1, "Concretization gave wrong result");
            nb += _assert( smulh(exprcst(32, -1), exprcst(32, -1))->concretize(&ctx) == 0, "Concretization gave wrong result");
            
            
            nb += _assert( (-v3)->concretize(&ctx) == 0x0001000000000000, "Concretization gave wrong result");
            nb += _assert( (~v4)->concretize(&ctx) == 0xffff000000000000, "Concretization gave wrong result");  
            nb += _assert( (v3^v4)->concretize(&ctx) == -1, "Concretization gave wrong result");
            nb += _assert( (v4&v3)->concretize(&ctx) == 0, "Concretization gave wrong result");
            nb += _assert( (v3|v4)->concretize(&ctx) == -1, "Concretization gave wrong result");
            nb += _assert( (v3*v4)->concretize(&ctx) == 0xffff000000000000*0x0000ffffffffffff, "Concretization gave wrong result");
            nb += _assert(( exprcst(32, 23)%exprcst(32, 2))->concretize(&ctx) == 1, "Concretization gave wrong result");
            nb += _assert(( exprcst(32, 20)%exprcst(32, 27))->concretize(&ctx) == 20, "Concretization gave wrong result");
            nb += _assert(( exprcst(32, 0xffffffff)%exprcst(32, 4))->concretize(&ctx) == 
                          ( exprcst(32, -1)%exprcst(32, 4))->concretize(&ctx), "Concretization gave wrong result");

            nb += _assert( v1->concretize(&ctx) != v1->concretize(&ctx2), "Concretization with different contexts gave same result");
            nb += _assert( v2->concretize(&ctx) != v2->concretize(&ctx2), "Concretization with different contexts gave same result"); 
            nb += _assert( v3->concretize(&ctx) != v3->concretize(&ctx2), "Concretization with different contexts gave same result"); 
            nb += _assert( v4->concretize(&ctx) != v4->concretize(&ctx2), "Concretization with different contexts gave same result"); 
            nb += _assert( (v1|v2)->concretize(&ctx) != (v1|v2)->concretize(&ctx2), "Concretization with different contexts gave same result");
            nb += _assert( e1->concretize(&ctx) != e1->concretize(&ctx2), "Concretization with different contexts gave same result"); 
            nb += _assert( e2->concretize(&ctx) != e2->concretize(&ctx2), "Concretization with different contexts gave same result"); 
            nb += _assert( e3->concretize(&ctx) != e3->concretize(&ctx2), "Concretization with different contexts gave same result"); 
            nb += _assert( e4->concretize(&ctx) != e4->concretize(&ctx2), "Concretization with different contexts gave same result"); 

            return nb;
        }
        
        unsigned int change_varctx(){
            unsigned int nb = 0; 
            VarContext ctx;
            Expr    v1 = exprvar(32, "var1" ),
                    v2 = exprvar(32, "var2"),
                    v3 = exprvar(64, "var3"),
                    v4 = exprvar(64, "var4"),
                    e1 = v1+v2, 
                    e2 = v3|v4;
            ctx.set("var1", 100);
            ctx.set("var2", -2);
            
            nb += _assert( v1->concretize(&ctx) == 100, "Concretization gave wrong result");
            nb += _assert( v2->concretize(&ctx) == -2, "Concretization gave wrong result"); 
            
            ctx.set("var1", 10);
            ctx.set("var3", 0xffff000000000000);
            ctx.set("var4", 0x0000ffffffffffff);
            
            nb += _assert( v1->concretize(&ctx) == 10, "Concretization gave wrong result");
            nb += _assert( v2->concretize(&ctx) == -2, "Concretization gave wrong result"); 
            nb += _assert( v3->concretize(&ctx) == 0xffff000000000000, "Concretization gave wrong result"); 
            nb += _assert( v4->concretize(&ctx) == 0x0000ffffffffffff, "Concretization gave wrong result"); 
            
            
            nb += _assert( e1->concretize(&ctx) == exprcst(32, 8)->concretize(&ctx), "Concretization gave wrong result"); 
            nb += _assert( e2->concretize(&ctx) == exprcst(64, -1)->concretize(&ctx), "Concretization gave wrong result"); 
            
            ctx.set("var2", -3);
            ctx.set("var4", 0xffff000000000000);
            
            nb += _assert( e1->concretize(&ctx) == exprcst(32, 7)->concretize(&ctx), "Concretization gave wrong result");
            nb += _assert( e2->concretize(&ctx) == exprcst(64, 0xffff000000000000)->concretize(&ctx), "Concretization gave wrong result");

            return nb;
        }

        unsigned int varctx_id(){
            unsigned int nb = 0;
            VarContext ctx, ctx2;
            varctx_id_t id;

            nb += _assert( ctx.id() != VARCTX_ID_NONE, "New context has the reserved id");
            nb += _assert( ctx.id() != ctx2.id(), "Two new contexts have the same id");

            id = ctx.id();
            ctx.set("var1", 1);
            nb += _assert( ctx.id() != id, "Adding a variable kept the id");
            id = ctx.id();
            ctx.set("var1", 1);
            nb += _assert( ctx.id() == id, "Setting a variable to its current value changed the id");
            ctx.set("var1", 2);
            nb += _assert( ctx.id() != id, "Changing a variable kept the id");
            id = ctx.id();
            ctx.remove("unknown");
            nb += _assert( ctx.id() == id, "Removing an unknown variable changed the id");
            ctx.remove("var1");
            nb += _assert( ctx.id() != id, "Removing a variable kept the id");

            // A copy shares the id until one of the contexts changes
            ctx.set("var1", 3);
            VarContext copy = ctx;
            nb += _assert( copy.id() == ctx.id(), "Copied context has a different id");
            copy.set("var1", 4);
            nb += _assert( copy.id() != ctx.id(), "Modified copy kept the id of the original");

            // Copies of one state (copy-constructed or assigned) must not take
            // the same next id
            VarContext a;
            a.set("var1", 1);
            VarContext b(a), c;
            c = a;
            b.set("var1", 2);
            c.set("var1", 3);
            a.set("var1", 4);
            nb += _assert( a.id() != b.id() && b.id() != c.id() && a.id() != c.id(), "Copies of a context reused an id");

            // Ids stay unique past the end of a context's block of ids
            std::set<varctx_id_t> ids;
            VarContext d, e;
            varslot_t slot = var_slot("var1");
            for( int i = 0; i < 70000; i++ ){
                d.set_slot(slot, i);
                ids.insert(d.id());
                e.set_slot(slot, i);
                ids.insert(e.id());
            }
            nb += _assert( ids.size() == 140000, "Two contexts reused an id");
            return nb;
        }

        // An expression shared between contexts must never return a value
        // cached under another context, even when both contexts went through
        // the same sequence of operations
        unsigned int shared_expr_varctx(){
            unsigned int nb = 0;
            Expr    v1 = exprvar(32, "var1"),
                    e1 = v1 + exprcst(32, 1);
            VarContext ctx;
            ctx.set("var1", 1);
            nb += _assert( e1->concretize(&ctx) == 2, "Concretization gave wrong result");

            VarContext ctx2;
            ctx2.set("var1", 5);
            nb += _assert( v1->concretize(&ctx2) == 5, "Concretization used a value cached under another context");
            nb += _assert( e1->concretize(&ctx2) == 6, "Concretization used a value cached under another context");

            // Unchanged contexts keep their cached values valid
            ctx2.set("var1", 5);
            nb += _assert( e1->concretize(&ctx2) == 6, "Concretization gave wrong result");
            nb += _assert( e1->concretize(&ctx) == 2, "Concretization used a value cached under another context");
            return nb;
        }

        unsigned int var_slots(){
            unsigned int nb = 0;
            varslot_t slot1 = var_slot("slot_test_var1"), slot2 = var_slot("slot_test_var2"), found;
            bool got_exception = false;

            // One slot per distinct name, for the whole process
            nb += _assert( slot1 != slot2, "Two names got the same slot");
            nb += _assert( var_slot("slot_test_var1") == slot1, "A name got two different slots");
            nb += _assert( var_slot_name(slot2) == "slot_test_var2", "Wrong name for a slot");
            nb += _assert( find_var_slot("slot_test_var1", found) && found == slot1, "find_var_slot() missed a name");
            size_t count = var_slot_count();
            nb += _assert( !find_var_slot("slot_test_never_added", found), "find_var_slot() found an unknown name");
            nb += _assert( var_slot_count() == count, "find_var_slot() added a name");

            // Setting by name or by slot is the same
            VarContext ctx;
            ctx.set("slot_test_var1", 10);
            ctx.set_slot(slot2, -2);
            nb += _assert( ctx.get_slot(slot1) == 10 && ctx.get("slot_test_var2") == -2, "Name and slot access disagree");
            nb += _assert( exprvar(32, "slot_test_var2")->concretize(&ctx) == -2, "Concretization by slot gave wrong result");

            // Unknown variables throw, whether looked up by name or by slot
            try{ ctx.get("slot_test_never_added"); }catch(expression_exception& e){ got_exception = true; }
            nb += _assert( got_exception, "Reading an unknown name should throw");
            got_exception = false;
            try{ ctx.get_slot(var_slot("slot_test_var3")); }catch(expression_exception& e){ got_exception = true; }
            nb += _assert( got_exception, "Reading an unset slot should throw");
            got_exception = false;
            ctx.remove("slot_test_var1");
            try{ ctx.get_slot(slot1); }catch(expression_exception& e){ got_exception = true; }
            nb += _assert( got_exception, "Reading a removed variable should throw");

            // Printing is sorted by name, not by slot
            VarContext ctx2;
            std::stringstream ss;
            ctx2.set("slot_test_var2", 2);
            ctx2.set("slot_test_var1", 1);
            ctx2.print(ss);
            nb += _assert( ss.str() == "\nslot_test_var1 : 0x1\nslot_test_var2 : 0x2\n", "Context printed in the wrong order");
            return nb;
        }

        // Renaming a variable must also forget the slot it cached
        unsigned int renamed_var_slot(){
            unsigned int nb = 0;
            Expr v = exprvar(32, "rename_test_var1");
            VarContext ctx, ctx2;
            ctx.set("rename_test_var1", 1);
            nb += _assert( v->concretize(&ctx) == 1, "Concretization gave wrong result");

            v->replace_name("rename_test_var2");
            ctx2.set("rename_test_var1", 7);
            ctx2.set("rename_test_var2", 5);
            nb += _assert( v->concretize(&ctx2) == 5, "Renamed variable read the value of its old name");
            return nb;
        }

    }
}

using namespace test::expression; 
// All unit tests 
void test_expression(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing expression module... " << std::flush;  
    total += basic();
    total += canonize();
    total += hashing();
    total += concretization();
    total += change_varctx();
    total += varctx_id();
    total += shared_expr_varctx();
    total += var_slots();
    total += renamed_var_slot();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
