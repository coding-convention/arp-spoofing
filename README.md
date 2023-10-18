# ARP Spoofing Tool

This project implements ARP spoofing using C++ and the pcap library. It is designed primarily for network study purposes.

> ⚠️ **Caution:** Never run this tool on a public Wi-Fi network. Using ARP spoofing maliciously or without permission can be illegal and unethical.

## 📚 Table of Contents

- [ARP Spoofing Tool](#arp-spoofing-tool)
  - [📚 Table of Contents](#-table-of-contents)
  - [🛠 Requirements](#-requirements)
  - [🚀 Installation](#-installation)
  - [🧑‍💻 Usage](#-usage)
  - [📜 License](#-license)

## 🛠 Requirements

- Operating System: Ubuntu 22.04
- Dependencies: g++, libpcap-dev, libgtest-dev

## 🚀 Installation

1. Clone this repository:
    ```bash
    git clone [repository-url]
    cd arp-spoofing-main
    ```

2. Install the required dependencies:
    ```bash
    sudo apt install g++ libpcap-dev libgtest-dev
    ```

3. Build the project:
    ```bash
    make
    ```

## 🧑‍💻 Usage

To run the ARP spoofing tool, use the following syntax:

```bash
./arp-spoof <interface> <sender ip> <target ip>
```

**Example:**

```bash
./arp-spoof wlan0 192.168.10.2 192.168.10.1 
```

## 📜 License

This project is open source and available under the [MIT License](LICENSE) (if applicable).