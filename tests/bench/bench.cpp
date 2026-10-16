/* ROPium profiling driver
 * =======================
 *
 * Loads a rp++ gadget file, analyses it, compiles ONE query and prints
 * timings + result. Meant to be built with 'make PROFILE=1 BINDINGS=0 bench'
 * and run under 'timeout -s INT <cap>' by tests/bench/profile.sh.
 *
 * Output (stdout, one item per line, stable format parsed by profile.sh):
 *     raw_gadgets <n>
 *     load_s <seconds>
 *     compile_s <seconds>
 *     FOUND            followed by the chain dump (one item per line)
 *  or NONE             (no chain, or search aborted by SIGINT)
 *  or INTERRUPTED      (SIGINT received while loading, compile skipped)
 *  or ERROR <message>
 *     cpu_s <seconds>  (user + sys CPU time of the whole process)
 *     maxrss_kb <n>    (peak resident set size)
 *
 * SIGINT handling: while ROPCompiler::compile() runs, ROPium installs its own
 * SIGINT handler which aborts the search cleanly (compile() returns nullptr).
 * Outside of compile() this driver's handler is active, so a SIGINT during
 * the load phase does not kill the process either. In every case main()
 * returns normally so that gmon.out gets written.
 */

#include "compiler.hpp"
#include "database.hpp"
#include "constraint.hpp"
#include "ropchain.hpp"
#include "arch.hpp"
#include "systems.hpp"
#include "utils.hpp"
#include "exception.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::vector;

static volatile sig_atomic_t g_bench_sigint = 0;

static void bench_sigint_handler(int s){
    g_bench_sigint = 1;
}

static void install_bench_sigint_handler(){
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = bench_sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Don't make file reads fail with EINTR during load
    sigaction(SIGINT, &sa, nullptr);
}

static double seconds_since(std::chrono::steady_clock::time_point start){
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

static void usage(const char* prog){
    cerr << "Usage: " << prog << " <rp++ gadget file> <query> [options]" << endl
         << "Options:" << endl
         << "    --unsafe                 allow unsafe memory dereferences (safe_mem = False)" << endl
         << "    --bad-bytes 00,0a,0d     comma separated list of bad bytes (hex)" << endl
         << "    --keep-regs esi,edi      comma separated list of registers to keep" << endl
         << "    --os linux|windows|none  target OS for syscalls (default: none)" << endl
         << "    --arch x86|x64           architecture (default: x86)" << endl;
}

static vector<string> split_list(const string& s){
    vector<string> res;
    std::stringstream ss(s);
    string item;
    while( std::getline(ss, item, ',')){
        if( !item.empty() )
            res.push_back(item);
    }
    return res;
}

// Per-process temp file for the raw gadgets (several benches can run in parallel)
static string make_tmp_raw_file(){
    const char* tmpdir = getenv("TMPDIR");
    string path = string((tmpdir && tmpdir[0]) ? tmpdir : "/tmp") + "/ropium_bench_raw.XXXXXX";
    vector<char> buf(path.begin(), path.end());
    buf.push_back('\0');
    int fd = mkstemp(buf.data());
    if( fd == -1 ){
        return "";
    }
    close(fd);
    return string(buf.data());
}

int main(int argc, char ** argv){
    string rp_file, query, arch_name = "x86", os_name = "none";
    string bad_bytes_str, keep_regs_str;
    bool unsafe = false;
    Arch* arch = nullptr;
    GadgetDB* db = nullptr;
    ROPCompiler* compiler = nullptr;
    Constraint* constraint = nullptr;
    ROPChain* ropchain = nullptr;
    vector<RawGadget>* raw = nullptr;
    System sys = System::NONE;
    string raw_file;
    int ret = 0;

    // Parse arguments
    vector<string> positional;
    for( int i = 1; i < argc; i++ ){
        string arg = argv[i];
        bool has_value = (i+1 < argc);
        if( arg == "--unsafe" ){
            unsafe = true;
        }else if( arg == "--bad-bytes" && has_value ){
            bad_bytes_str = argv[++i];
        }else if( arg == "--keep-regs" && has_value ){
            keep_regs_str = argv[++i];
        }else if( arg == "--os" && has_value ){
            os_name = argv[++i];
        }else if( arg == "--arch" && has_value ){
            arch_name = argv[++i];
        }else if( arg == "-h" || arg == "--help" ){
            usage(argv[0]);
            return 0;
        }else if( arg.size() > 1 && arg[0] == '-' && arg[1] == '-' ){
            cerr << "Unknown or incomplete option: " << arg << endl;
            usage(argv[0]);
            return 1;
        }else{
            positional.push_back(arg);
        }
    }
    if( positional.size() != 2 ){
        usage(argv[0]);
        return 1;
    }
    rp_file = positional[0];
    query = positional[1];

    install_bench_sigint_handler();
    disable_colors(); // Plain chain dump

    try{
        // Architecture / OS
        if( arch_name == "x86" ){
            arch = new ArchX86();
        }else if( arch_name == "x64" ){
            arch = new ArchX64();
        }else{
            throw runtime_exception("unsupported arch: " + arch_name);
        }
        if( os_name == "linux" ){
            sys = System::LINUX;
        }else if( os_name == "windows" ){
            sys = System::WINDOWS;
        }else if( os_name != "none" ){
            throw runtime_exception("unsupported os: " + os_name);
        }

        // Constraint (same defaults as the python bindings: safe memory)
        constraint = new Constraint();
        if( unsafe ){
            constraint->mem_safety.enable_unsafe();
        }
        for( string& b : split_list(bad_bytes_str)){
            constraint->bad_bytes.add_bad_byte((unsigned char)strtoul(b.c_str(), nullptr, 16));
        }
        for( string& r : split_list(keep_regs_str)){
            constraint->keep_regs.add_keep_reg(arch->reg_num(r)); // throws on unknown reg
        }

        cout << "bench_file " << rp_file << endl
             << "bench_query " << query << endl
             << "bench_options arch=" << arch_name << " os=" << os_name << " unsafe=" << (unsafe ? 1 : 0)
             << " bad_bytes=" << bad_bytes_str << " keep_regs=" << keep_regs_str << endl;

        // Load: same sequence as ROPium.load_rp() in the python bindings
        raw_file = make_tmp_raw_file();
        if( raw_file.empty() ){
            throw runtime_exception("couldn't create temporary raw gadget file");
        }
        db = new GadgetDB();
        compiler = new ROPCompiler(arch, db);

        auto t_load = std::chrono::steady_clock::now();
        if( !rp_gadgets_to_file(raw_file, rp_file)){
            throw runtime_exception("couldn't read input file " + rp_file);
        }
        raw = raw_gadgets_from_file(raw_file);
        remove(raw_file.c_str());
        if( !raw ){
            throw runtime_exception("failed to load raw gadgets");
        }
        db->analyse_raw_gadgets(*raw, arch);
        double load_s = seconds_since(t_load);
        cout << "raw_gadgets " << raw->size() << endl;
        cout << std::fixed << std::setprecision(3) << "load_s " << load_s << endl;
        delete raw; raw = nullptr;

        if( g_bench_sigint ){
            // SIGINT arrived while loading: don't start the search
            cout << "compile_s " << 0.0 << endl;
            cout << "INTERRUPTED" << endl;
        }else{
            // Compile (ROPium's SIGINT handler aborts the search -> nullptr)
            auto t_compile = std::chrono::steady_clock::now();
            ropchain = compiler->compile(query, constraint, ABI::NONE, sys);
            double compile_s = seconds_since(t_compile);
            cout << "compile_s " << compile_s << endl;
            if( ropchain ){
                cout << "FOUND" << endl;
                ropchain->print_pretty(cout, "    ");
            }else{
                cout << "NONE" << endl;
            }
        }
    }catch(std::exception& e){
        // il_exception (bad query), compiler_exception, runtime_exception, ...
        cout << "ERROR " << e.what() << endl;
        ret = 2;
    }
    if( !raw_file.empty() ){
        remove(raw_file.c_str()); // No-op if already removed
    }

    // CPU time vs wall time shows how much the run was slowed by machine load
    struct rusage ru;
    if( getrusage(RUSAGE_SELF, &ru) == 0 ){
        double cpu_s = ru.ru_utime.tv_sec + ru.ru_stime.tv_sec
                     + (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6;
        cout << std::fixed << std::setprecision(3) << "cpu_s " << cpu_s << endl;
        cout << "maxrss_kb " << ru.ru_maxrss << endl;
    }
    cout.flush();

    // The gadget database is intentionally not freed: its destructor would
    // only add teardown noise to the profile and the process exits anyway.
    delete raw; raw = nullptr;
    delete ropchain; ropchain = nullptr;
    delete compiler; compiler = nullptr;
    delete constraint; constraint = nullptr;
    delete arch; arch = nullptr;
    return ret;
}
