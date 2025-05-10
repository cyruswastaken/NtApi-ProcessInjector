# NtApi-ProcessInjector

A lightweight proof-of-concept (PoC) demonstrating manual invocation of undocumented Windows NTAPI functions for advanced process manipulation. This project showcases how to use low-level system calls like `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtCreateThreadEx` without relying on higher-level Windows APIs.

## ⚙️ Features

- Dynamic resolution of NTAPI functions from `ntdll.dll`
- Manual remote thread creation using `NtCreateThreadEx`
- Demonstrates usage of `OBJECT_ATTRIBUTES`, `CLIENT_ID`, and other native structures
- Cleanly structured and documented for learning and experimentation

## 🚨 Disclaimer

This code is intended **for educational and research purposes only**. Do not use it on unauthorized systems. You are responsible for complying with your local laws and regulations.

## 🧱 Requirements

- Windows (x64)
- Visual Studio (or any modern C++ compiler)
- Basic understanding of Windows internals and NTAPI

## ^-^
