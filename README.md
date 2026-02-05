# Windows Cryptography Research Project

This project is a C++ research implementation focused on studying how
Windows cryptographic APIs (DPAPI and CNG / BCrypt) work in practice.

The code demonstrates:
- Interaction with Windows-specific cryptographic services
- File system access using C++17 (`std::filesystem`)
- JSON parsing using `nlohmann::json`
- Handling encrypted data formats commonly found in desktop applications

## ⚠️ Important Notice

This repository is intended **strictly for educational, academic, and research purposes**.
It is designed to help developers understand:
- How encryption keys may be protected by the operating system
- How authenticated encryption (AES-GCM) works at a low level
- How real-world applications store encrypted data locally

No part of this project is intended for misuse.

## 🧠 Educational Topics Covered

- Windows DPAPI (`CryptUnprotectData`)
- Windows CNG / BCrypt API
- AES-GCM encryption and decryption concepts
- Base64 encoding/decoding
- Secure memory handling
- File parsing and binary data processing

## 🛠 Platform

- Windows only
- Requires Windows Cryptography APIs
- C++17 compatible compiler

## 📚 Disclaimer

See the DISCLAIMER section below.
