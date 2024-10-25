//old version 2023
#include <iostream>
#include <fstream>
#include <Windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <vector>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

class Kerpy {
public:
    void registryCheck() {
        std::string cmd = "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\";
        if (system((cmd + "DriverDesc").c_str()) == 0 || system((cmd + "ProviderName").c_str()) == 0) {
            std::cout << "VMware Registry Detected" << std::endl;
            exit(0);
        }
    }

    void processesAndFilesCheck() {
        std::string vmwareDll = getenv("SystemRoot");
        vmwareDll += "\\System32\\vmGuestLib.dll";
        std::string virtualboxDll = getenv("SystemRoot");
        virtualboxDll += "\\vboxmrxnp.dll";

        std::string process;
        FILE* pipe = _popen("TASKLIST /FI \"STATUS eq RUNNING\" | find /V \"Image Name\" | find /V \"=\"", "r");
        char buffer[128];
        while (fgets(buffer, 128, pipe) != NULL) {
            process += buffer;
        }
        _pclose(pipe);

        std::vector<std::string> processList;
        size_t pos = 0;
        while ((pos = process.find(".exe", pos)) != std::string::npos) {
            processList.push_back(process.substr(0, pos + 4));
            pos += 4;
        }

        if (std::find(processList.begin(), processList.end(), "VMwareService.exe") != processList.end() ||
            std::find(processList.begin(), processList.end(), "VMwareTray.exe") != processList.end()) {
            std::cout << "VMwareService.exe & VMwareTray.exe process are running" << std::endl;
            exit(0);
        }

        if (GetFileAttributes(vmwareDll.c_str()) != INVALID_FILE_ATTRIBUTES) {
            std::cout << "Vmware DLL Detected" << std::endl;
            exit(0);
        }

        if (GetFileAttributes(virtualboxDll.c_str()) != INVALID_FILE_ATTRIBUTES) {
            std::cout << "VirtualBox DLL Detected" << std::endl;
            exit(0);
        }

        HMODULE sandboxieDll = LoadLibrary("SbieDll.dll");
        if (sandboxieDll != NULL) {
            std::cout << "Sandboxie DLL Detected" << std::endl;
            FreeLibrary(sandboxieDll);
            exit(0);
        }

        std::ifstream processListFile("https://pastebin.com/raw/Xe5WMsTU");
        std::string processl;
        while (std::getline(processListFile, processl)) {
            if (std::find(processList.begin(), processList.end(), processl) != processList.end()) {
                exit(0);
            }
        }
    }

    void macCheck() {
        std::string macAddress = "00:00:00:00:00:00"; // Placeholder for getting MAC Address
        std::ifstream macListFile("https://pastebin.com/raw/ftd50eAq");
        std::string mac;
        while (std::getline(macListFile, mac)) {
            if (macAddress.substr(0, 8) == mac) {
                std::cout << "VMware MAC Address Detected" << std::endl;
                exit(0);
            }
        }
    }

    void checkPc() {
        std::string vmName;
        std::string vmNameFileContent;
        std::ifstream vmNameFile("https://pastebin.com/raw/jnEaykLU");
        std::getline(vmNameFile, vmNameFileContent);
        if (vmName == vmNameFileContent) {
            exit(0);
        }

        std::string vmUsername;
        std::string hostName;
        char hostNameBuffer[1024];
        gethostname(hostNameBuffer, 1024);
        hostName = hostNameBuffer;
        std::ifstream vmUsernameFile("https://pastebin.com/raw/Vgztru48");
        std::getline(vmUsernameFile, vmUsername);
        if (hostName == vmUsername) {
            exit(0);
        }
    }

    void hwidVm() {
        std::string currentMachineId; // Placeholder for getting machine ID
        std::ifstream hwidVmFile("https://pastebin.com/raw/E5pwq7NH");
        std::string hwid;
        while (std::getline(hwidVmFile, hwid)) {
            if (currentMachineId == hwid) {
                exit(0);
            }
        }
    }

    void checkGpu() {
        std::string gpuDescription;
        std::ifstream gpuListFile("https://pastebin.com/raw/LSpkCfqc");
        std::string gpu;
        while (std::getline(gpuListFile, gpu)) {
            if (gpuDescription == gpu) {
                exit(0);
            }
        }
    }

    void checkIp() {
        std::ifstream ipListFile("https://pastebin.com/raw/tDXxxRUc");
        std::vector<std::string> ipList;
        std::string ip;
        while (std::getline(ipListFile, ip)) {
            ipList.push_back(ip);
        }

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed" << std::endl;
            return;
        }

        char ipBuffer[100];
        if (gethostname(ipBuffer, sizeof(ipBuffer)) == SOCKET_ERROR) {
            std::cerr << "Error getting hostname: " << WSAGetLastError() << std::endl;
            WSACleanup();
            return;
        }
        hostent* host;
        host = gethostbyname(ipBuffer);
        if (host == NULL) {
            std::cerr << "Error getting IP address" << std::endl;
            WSACleanup();
            return;
        }
        std::string ipAddr = inet_ntoa(*(struct in_addr*)*host->h_addr_list);

        if (std::find(ipList.begin(), ipList.end(), ipAddr) != ipList.end()) {
            exit(0);
        }

        WSACleanup();
    }

    void profiles() {
        std::string machineGuid = "00000000-0000-0000-0000-000000000000"; // Placeholder for getting machine GUID
        std::ifstream guidPcFile("https://pastebin.com/raw/vrkN6wA1");
        std::string guidPc;
        while (std::getline(guidPcFile, guidPc)) {
            if (machineGuid == guidPc) {
                exit(0);
            }
        }

        std::ifstream biosGuidFile("https://pastebin.com/raw/T1x6YGbZ");
        std::string biosGuid;
        while (std::getline(biosGuidFile, biosGuid)) {
            if (true /* Condition for comparison */) {
                exit(0);
            }
        }

        std::ifstream baseboardGuidFile("https://pastebin.com/raw/RuXc6in9");
        std::string baseboardGuid;
        while (std::getline(baseboardGuidFile, baseboardGuid)) {
            if (true /* Condition for comparison */) {
                exit(0);
            }
        }

        std::ifstream serialDiskFile("https://pastebin.com/raw/VcuTddgf");
        std::string diskSerial;
        while (std::getline(serialDiskFile, diskSerial)) {
            if (true /* Condition for comparison */) {
                exit(0);
            }
        }
    }
};

int main() {
    Kerpy kerpy;
    kerpy.registryCheck();
    kerpy.processesAndFilesCheck();
    kerpy.macCheck();
    kerpy.checkPc();
    kerpy.hwidVm();
    kerpy.checkGpu();
    kerpy.checkIp();
    kerpy.profiles();
    return 0;
}
