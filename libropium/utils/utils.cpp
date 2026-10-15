#include "utils.hpp"
#include "exception.hpp"
#include <iostream>
#include <fstream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <vector>
#include <exception>
#include <signal.h>
#include <regex>
#include <codecvt>
#include <locale>
#include <iomanip>
#include <cstring>

using std::ifstream;
using std::ofstream;
using std::ios;
using std::stringstream;
using std::vector;

/* ======== Raw gadgets interface ======== */
// Read gadgets from file
vector<RawGadget>* raw_gadgets_from_file(string filename){
    vector<RawGadget>* res = new vector<RawGadget>();
    RawGadget raw;
    bool got_addr;
    ifstream file;
    string line;
    string addr_str;
    string byte;
    
    file.open(filename, ios::in | ios::binary );
    while( getline(file, line)){
        raw = RawGadget();
        got_addr = false;
        addr_str = "";
        byte = "";
        for( char& c : line ){
            // First the gadget address
            if( c == '$' ){
                try{
                    raw.addr = std::stoi(addr_str, 0, 16);
                    if( raw.addr == 0 )
                        throw std::invalid_argument("");
                    got_addr = true;
                }catch(std::invalid_argument& e){
                    throw runtime_exception(QuickFmt() << "raw_gadgets_from_file: error, bad address string: " << line >> QuickFmt::to_str);
                }
            }else if( !got_addr){
                addr_str += c;
            }else{
                byte += c;
                if( byte.size() == 2 ){
                    try{
                        raw.raw += (char)(std::stoi(byte, 0, 16));
                        byte = "";
                    }catch(std::invalid_argument& e){
                        throw runtime_exception(QuickFmt() << "raw_gadgets_from_file: error, bad byte in: " << line >> QuickFmt::to_str);
                    }
                }
            }
        }
        res->push_back(raw);
    }
    
    file.close();
    return res;
}


// Write gadgets to file from ROPgadget output
void split(const std::string& str, vector<string>& cont, char delim = ' ')
{
    std::size_t current, previous = 0;
    current = str.find(delim);
    while (current != std::string::npos) {
        cont.push_back(str.substr(previous, current - previous));
        previous = current + 1;
        current = str.find(delim, previous);
    }
    cont.push_back(str.substr(previous, current - previous));
}

bool ropgadget_to_file(string out, string ropgadget_out, string bin){
    stringstream cmd;
    ofstream out_file;
    ifstream ropgadget_file;
    string line;

    out_file.open(out, ios::out);

    cmd << "ROPgadget --binary " << bin << " --dump --all --depth 15 > " << ropgadget_out << std::endl; 
    try{

        FILE* pipe = popen(cmd.str().c_str(), "w");
        string addr_str, raw_str;
        stringstream ss;
        vector<string> splited;


        if (!pipe) {
            throw std::runtime_error("popen() failed!");
        }

        pclose(pipe);
        ropgadget_file.open(ropgadget_out, ios::in);
        
        while( std::getline(ropgadget_file, line)){
            splited.clear();
            split(line, splited);

            // Get address string
            if( splited.size() > 3 ){
                addr_str = splited[0];
            }else{
                continue;
            }
            if( addr_str.substr(0, 2) != "0x" ){
                continue;
            }
            // Get raw string
            raw_str = splited.back();
            if( raw_str.back() != '\n' )
                raw_str += '\n';

            // Write them to file
            out_file << addr_str << "$" << raw_str;
        }

    }catch(std::runtime_error& e){
        return false;
    }

    out_file.close();
    ropgadget_file.close();
    return true;
}

bool rp_gadgets_to_file(string output_file_path, string input_file_path){
    std::cout << "Start rp_gadgets_to_file. Out: " << output_file_path << " Input: " << input_file_path << std::endl;
    stringstream cmd;
    ofstream out_file;
    ifstream ropgadget_file;
    string line;
    int counter = 0;
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

    try{
        out_file.open(output_file_path, ios::out);
        string addr_str, raw_str;
        stringstream ss;
        vector<string> splited;
        ropgadget_file.open(input_file_path, ios::in);
        if (!ropgadget_file.is_open()) {
            std::cerr << "Error: Could not open file: " << input_file_path
                      << " (" << std::strerror(errno) << ")" << std::endl;
            return false;
        }
        std::regex pattern(R"(\(\d+ found\))");
        while( std::getline(ropgadget_file, line)){
            std::wstring line_wstr = converter.from_bytes(line);
            std::string line_str = converter.to_bytes(line_wstr);
            line = line_str;
            line = std::regex_replace(line, pattern, "");
            // Trim trailing whitespace
            line = std::regex_replace(line, std::regex("\\s+$"), "");
            splited.clear();
            // Split on spaces
            split(line, splited);
            // Get address string
            if( splited.size() > 3 ){
                addr_str = splited[0];
            }else{
                continue;
            }
            if( addr_str.substr(0, 2) != "0x" ){
                continue;
            }
            // Get raw string - last element of the split
            raw_str = splited.back();
            if (raw_str.find("\\x") != std::string::npos) {
                size_t pos = 0;
                while ((pos = raw_str.find("\\x", pos)) != std::string::npos) {
                    raw_str.erase(pos, 2);
                }
            }
            if( raw_str.back() != '\n' )
                raw_str += '\n';

            counter++;
            std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
            std::wstring addr_wstr = std::wstring(addr_str.begin(), addr_str.end());
            std::string addr_utf8 = conv.to_bytes(addr_wstr);
            std::wstring raw_wstr = std::wstring(raw_str.begin(), raw_str.end());
            std::string raw_utf8 = conv.to_bytes(raw_wstr);
            out_file << addr_utf8 << "$" << raw_utf8;
        }

    }catch(std::runtime_error& e){
        std::cerr << "Runtime error: " << e.what() << std::endl;
        return false;
    }catch(...){
        std::cerr << "Unknown error occurred." << std::endl;
        return false;
    }

    std::cout << "Gadgets written to file: " << counter << std::endl;
    out_file.close();
    ropgadget_file.close();
    return true;
}


/* ========== Printing stuff ============== */

// Colors 
string g_ERROR_COLOR_ANSI = DEFAULT_ERROR_COLOR_ANSI;
string g_BOLD_COLOR_ANSI = DEFAULT_BOLD_COLOR_ANSI;
string g_SPECIAL_COLOR_ANSI = DEFAULT_SPECIAL_COLOR_ANSI;
string g_PAYLOAD_COLOR_ANSI = DEFAULT_PAYLOAD_COLOR_ANSI;
string g_EXPLOIT_DESCRIPTION_ANSI = DEFAULT_EXPLOIT_DESCRIPTION_ANSI;
string g_END_COLOR_ANSI = DEFAULT_END_COLOR_ANSI ;

// String coloration 
string str_bold(string s){
    return g_BOLD_COLOR_ANSI + s + g_END_COLOR_ANSI; 
}

string str_special(string s){
    return g_SPECIAL_COLOR_ANSI + s + g_END_COLOR_ANSI; 
}

string value_to_hex_str(int octets, addr_t addr){
    char res[32], format[32];
    // Get format (32 or 64 bits)
    snprintf(format, sizeof(format), "%%0%02dllx", octets*2);
    // Write hex bytes 
    snprintf(res, sizeof(res), format, addr);
    return "0x"+string(res);
}

void disable_colors(){
    g_ERROR_COLOR_ANSI = "";
    g_BOLD_COLOR_ANSI = "";
    g_SPECIAL_COLOR_ANSI = "";
    g_PAYLOAD_COLOR_ANSI = "";
    g_EXPLOIT_DESCRIPTION_ANSI = "";
    g_END_COLOR_ANSI = "";
}

void enable_colors(){
    g_ERROR_COLOR_ANSI = DEFAULT_ERROR_COLOR_ANSI;
    g_BOLD_COLOR_ANSI = DEFAULT_BOLD_COLOR_ANSI;
    g_SPECIAL_COLOR_ANSI = DEFAULT_SPECIAL_COLOR_ANSI;
    g_PAYLOAD_COLOR_ANSI = DEFAULT_PAYLOAD_COLOR_ANSI;
    g_EXPLOIT_DESCRIPTION_ANSI = DEFAULT_EXPLOIT_DESCRIPTION_ANSI;
    g_END_COLOR_ANSI = DEFAULT_END_COLOR_ANSI ;    
}



/* ========= Catching ctrl+C ============= */
struct sigaction g_ropium_sigint_handler;
struct sigaction g_ropium_prev_sigint_handler;
bool g_ropium_sigint_flag = false;

void ropium_sigint_handler(int s){
    g_ropium_sigint_flag = true;
}

void set_sigint_handler(){
    g_ropium_sigint_handler.sa_handler = ropium_sigint_handler;
    sigemptyset(&g_ropium_sigint_handler.sa_mask);
    g_ropium_sigint_handler.sa_flags = 0;

    sigaction(SIGINT, &g_ropium_sigint_handler, &g_ropium_prev_sigint_handler);
}

void unset_signint_handler(){
    sigaction(SIGINT, &g_ropium_prev_sigint_handler, nullptr);
}

bool is_pending_sigint(){
    return g_ropium_sigint_flag;
}

void notify_sigint_handled(){
    g_ropium_sigint_flag = false;
}
