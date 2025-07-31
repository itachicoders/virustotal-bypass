#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <sstream>
#include <map>
#include <fstream>
#include <thread>
#include <chrono>
#include <random>
#include <algorithm>
#include <Windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <TlHelp32.h>
#include <winreg.h>
#include <intrin.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include "Kerpy.cpp"

class SystemAnalyzer {
private:
    struct AnalysisResult {
        bool found;
        std::string identifier;
        std::string details;
    };

    std::map<std::string, AnalysisResult> findings;
    bool detailed;
    std::vector<std::function<void()>> checks;

    std::string getNetworkAddress() {
        IP_ADAPTER_INFO* adapter_info = static_cast<IP_ADAPTER_INFO*>(malloc(sizeof(IP_ADAPTER_INFO)));
        ULONG buffer_len = sizeof(IP_ADAPTER_INFO);

        if (GetAdaptersInfo(adapter_info, &buffer_len) == ERROR_BUFFER_OVERFLOW) {
            free(adapter_info);
            adapter_info = static_cast<IP_ADAPTER_INFO*>(malloc(buffer_len));
        }

        std::string address;
        if (GetAdaptersInfo(adapter_info, &buffer_len) == NO_ERROR) {
            std::stringstream ss;
            for (UINT i = 0; i < adapter_info->AddressLength; i++) {
                if (i > 0) ss << ":";
                ss << std::hex << std::setw(2) << std::setfill('0') 
                   << static_cast<int>(adapter_info->Address[i]);
            }
            address = ss.str();
        }

        free(adapter_info);
        return address;
    }

    std::string getNetworkIP() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return "0.0.0.0";
        }

        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) != 0) {
            WSACleanup();
            return "0.0.0.0";
        }

        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
            WSACleanup();
            return "0.0.0.0";
        }

        char ipAddress[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, ipAddress, INET_ADDRSTRLEN);
        
        freeaddrinfo(res);
        WSACleanup();
        
        return std::string(ipAddress);
    }

    std::string getSystemId() {
        HKEY key_handle;
        std::string system_id;
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                          "SOFTWARE\\Microsoft\\Cryptography", 
                          0, KEY_READ, &key_handle) == ERROR_SUCCESS) {
            char buffer[255];
            DWORD buffer_size = sizeof(buffer);
            DWORD type;
            
            if (RegQueryValueExA(key_handle, "MachineGuid", NULL, &type,
                                (LPBYTE)buffer, &buffer_size) == ERROR_SUCCESS) {
                system_id = std::string(buffer);
            }
            
            RegCloseKey(key_handle);
        }
        
        return system_id;
    }

    std::string getGraphicsInfo() {
        std::string graphics_info;
        
        HKEY key_handle;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", 
                         0, KEY_READ, &key_handle) == ERROR_SUCCESS) {
            char buffer[255];
            DWORD buffer_size = sizeof(buffer);
            DWORD type;
            
            if (RegQueryValueExA(key_handle, "DriverDesc", NULL, &type,
                                (LPBYTE)buffer, &buffer_size) == ERROR_SUCCESS) {
                graphics_info = std::string(buffer);
            }
            
            RegCloseKey(key_handle);
        }
        
        return graphics_info;
    }

    std::string getSystemUser() {
        char buffer[256];
        DWORD buffer_size = sizeof(buffer);
        
        if (GetUserNameA(buffer, &buffer_size)) {
            return std::string(buffer);
        }
        
        return "User";
    }

    std::string runCommand(const std::string& cmd) {
        std::array<char, 256> buffer;
        std::string result;
        
        std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd.c_str(), "r"), _pclose);
        if (!pipe) {
            return "";
        }
        
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        
        return result;
    }

    int64_t getPerformanceFrequency() {
        LARGE_INTEGER frequency;
        QueryPerformanceFrequency(&frequency);
        return frequency.QuadPart;
    }

    int64_t getPerformanceCounter() {
        LARGE_INTEGER counter;
        QueryPerformanceCounter(&counter);
        return counter.QuadPart;
    }

    void checkVirtualizationTechniques() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(50, 150);

        auto randomSleep = [&]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(distrib(gen)));
        };

        bool indicator_found = false;
        
        randomSleep();
        
        struct StorageDeviceInfo {
            std::string registry_path;
            std::string value_name;
            std::vector<std::string> virtual_indicators;
        };
        
        std::vector<StorageDeviceInfo> checks = {
            {
                "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
                "Identifier",
                {"VMWARE", "VBOX", "QEMU", "VIRTUAL", "INNOTEK", "MICROSOFT"}
            },
            {
                "HARDWARE\\Description\\System\\BIOS",
                "SystemManufacturer",
                {"VMWARE", "VIRTUALBOX", "QEMU", "MICROSOFT CORPORATION"}
            },
            {
                "HARDWARE\\Description\\System\\BIOS",
                "SystemProductName",
                {"VIRTUAL", "VM", "HVM", "VMWARE", "VIRTUALBOX"}
            }
        };
        
        for (const auto& check : checks) {
            HKEY key_handle;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, check.registry_path.c_str(), 0, KEY_READ, &key_handle) == ERROR_SUCCESS) {
                char buffer[255];
                DWORD buffer_size = sizeof(buffer);
                DWORD type;
                
                if (RegQueryValueExA(key_handle, check.value_name.c_str(), NULL, &type, (LPBYTE)buffer, &buffer_size) == ERROR_SUCCESS) {
                    std::string value = std::string(buffer);
                    std::transform(value.begin(), value.end(), value.begin(), ::toupper);
                    
                    for (const auto& indicator : check.virtual_indicators) {
                        if (value.find(indicator) != std::string::npos) {
                            findings["SystemEnvironment"] = { true, "SystemReliability", 
                                                           "Reliability test pattern alpha failed: " + std::to_string(GetTickCount64()) };
                            indicator_found = true;
                            break;
                        }
                    }
                }
                
                RegCloseKey(key_handle);
                if (indicator_found) break;
            }
            
            randomSleep();
        }

        int cpu_info[4] = {0};
        __cpuid(cpu_info, 1);
        
        if ((cpu_info[2] >> 31) & 1) {
            findings["HVPresence"] = { true, "SystemArchitecture", 
                                   "Architecture review indicated non-standard patterns: " + std::to_string(GetTickCount64()) };
        }
        
        randomSleep();
        
        std::vector<std::string> files_to_check = {
            "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
            "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
            "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
            "C:\\Windows\\System32\\drivers\\vm3dgl.dll",
            "C:\\Windows\\System32\\drivers\\vmGuestLib.dll"
        };
        
        for (const auto& file : files_to_check) {
            DWORD attr = GetFileAttributesA(file.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES) {
                findings["SystemResource"] = { true, "ResourcePattern", 
                                          "Resource pattern identification failure: " + std::to_string(GetTickCount64()) };
                break;
            }
            
            randomSleep();
        }
    }

    void checkOperationalEnvironment() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(20, 80);

        auto randomSleep = [&]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(distrib(gen)));
        };

        std::vector<std::string> process_list = {
            "wireshark.exe", "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe",
            "autoruns.exe", "autorunsc.exe", "filemon.exe", "regmon.exe", "idaq.exe", 
            "idaq64.exe", "ImmunityDebugger.exe", "ollydbg.exe", "dumpcap.exe", 
            "HookExplorer.exe", "ImportREC.exe", "PETools.exe", "LordPE.exe", 
            "SysInspector.exe", "tcpview.exe", "die.exe"
        };
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(snapshot, &pe32)) {
                do {
                    for (const auto& process : process_list) {
                        if (_stricmp(pe32.szExeFile, process.c_str()) == 0) {
                            findings["ProcessMonitor"] = { true, "OperationalMonitoring", 
                                                       "Operational monitoring detected unexpected patterns: " + std::to_string(GetTickCount64()) };
                            CloseHandle(snapshot);
                            return;
                        }
                    }
                    randomSleep();
                } while (Process32Next(snapshot, &pe32));
            }
            
            CloseHandle(snapshot);
        }
        
        randomSleep();
        
        double start_time = static_cast<double>(getPerformanceCounter());
        double freq = static_cast<double>(getPerformanceFrequency());
        
        for (int i = 0; i < 100000; i++) {
            double x = std::sqrt(static_cast<double>(i));
        }
        
        Sleep(500);
        
        double end_time = static_cast<double>(getPerformanceCounter());
        double elapsed_seconds = (end_time - start_time) / freq;
        
        if (elapsed_seconds < 0.4 || elapsed_seconds > 0.6) {
            findings["TimeAnalysis"] = { true, "TemporalInconsistency", 
                                    "Temporal analysis revealed inconsistent execution patterns: " + std::to_string(GetTickCount64()) };
        }
    }

    void checkDebuggingEnvironment() {
        if (IsDebuggerPresent()) {
            findings["DebuggerDetection"] = { true, "ExecutionContext", 
                                         "Execution context analysis revealed abnormal patterns: " + std::to_string(GetTickCount64()) };
            return;
        }
        
        BOOL remote_debugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger);
        if (remote_debugger) {
            findings["RemoteDebugger"] = { true, "RemoteExecution", 
                                      "Remote execution context analysis failed: " + std::to_string(GetTickCount64()) };
            return;
        }
        
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        HANDLE thread = GetCurrentThread();
        
        if (GetThreadContext(thread, &ctx)) {
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                findings["ExecutionRegisters"] = { true, "RegisterAnalysis", 
                                             "Register state analysis detected inconsistencies: " + std::to_string(GetTickCount64()) };
                return;
            }
        }
        
        HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, "Global\\ScyllaHideNotification");
        if (hEvent && GetLastError() != ERROR_ALREADY_EXISTS) {
            findings["AntiDebugSoftware"] = { true, "SoftwareInterference", 
                                         "Software compatibility test failed: " + std::to_string(GetTickCount64()) };
            CloseHandle(hEvent);
            return;
        }
        
        uint32_t tick_count = GetTickCount();
        Sleep(10);
        uint32_t tick_count_2 = GetTickCount();
        
        if (tick_count_2 - tick_count < 5) {
            findings["TimeManipulation"] = { true, "SystemClockAnalysis", 
                                        "System clock analysis revealed irregularities: " + std::to_string(GetTickCount64()) };
        }
        
        CONTEXT context;
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &context)) {
            if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0) {
                findings["DebugRegisters"] = { true, "HardwareMonitoring", 
                                          "Hardware monitoring detected unauthorized activity: " + std::to_string(GetTickCount64()) };
            }
        }
    }
    
    void initializeChecks() {
        checks.push_back([this]() { checkVirtualizationTechniques(); });
        checks.push_back([this]() { checkOperationalEnvironment(); });
        checks.push_back([this]() { checkDebuggingEnvironment(); });
    }

public:
    SystemAnalyzer(bool show_details = false) : detailed(show_details) {
        initializeChecks();
    }

    void runAnalysis() {
        for (const auto& check : checks) {
            check();
        }
    }

    void generateReport() {
        bool any_findings = false;
        
        std::cout << "\n=== System Analysis Report ===\n" << std::endl;
        
        for (const auto& [key, result] : findings) {
            if (result.found) {
                any_findings = true;
                std::cout << "[ALERT] " << result.identifier << std::endl;
                
                if (detailed) {
                    std::cout << "  Details: " << result.details << std::endl;
                }
            }
        }
        
        if (!any_findings) {
            std::cout << "Environment appears to be standard." << std::endl;
        }
        
        std::cout << "\n=== System Configuration ===\n" << std::endl;
        std::cout << "Network: " << getNetworkIP() << std::endl;
        std::cout << "Hardware Address: " << getNetworkAddress() << std::endl;
        std::cout << "System Identifier: " << getSystemId() << std::endl;
        std::cout << "Graphics: " << getGraphicsInfo() << std::endl;
        std::cout << "User: " << getSystemUser() << std::endl;
    }
};

int main(int argc, char* argv[]) {
    bool detailed_mode = false;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-d" || arg == "--details") {
            detailed_mode = true;
        }
    }
    
    std::cout << "System Configuration Analyzer" << std::endl;
    std::cout << "---------------------------" << std::endl;
    std::cout << "Analyzing system configuration..." << std::endl;
    
    // First run Kerpy's checks to detect analysis environments
    Kerpy kerpy;
    kerpy.runAllChecks();
    
    if (kerpy.isAnalysisEnvironmentDetected()) {
        if (detailed_mode) {
            std::cout << "\nEnvironment check failed. Issues detected:" << std::endl;
            for (const auto& issue : kerpy.getFailedChecks()) {
                std::cout << " - " << issue << std::endl;
            }
        }
        return 0;
    }
    
    // If no issues detected, proceed with system analysis
    SystemAnalyzer analyzer(detailed_mode);
    analyzer.runAnalysis();
    analyzer.generateReport();
    
    return 0;
}