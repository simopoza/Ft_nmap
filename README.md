```
# ft_nmap

## 📌 Overview
`ft_nmap` is a custom implementation of a network port scanner inspired by Nmap.
It is designed to analyze network security by detecting open ports, identifying services, and performing multiple types of scans.

This project focuses on low-level network programming using raw packets, multithreading, and packet capture.

---

## 🚀 Features

- 🔍 Multiple scan types:
  - SYN
  - NULL
  - ACK
  - FIN
  - XMAS
  - UDP

- ⚡ Multithreading support (up to 250 threads)
- 🌐 Scan a single IP or multiple targets from a file
- 🎯 Port selection:
  - Single ports
  - Ranges (e.g., `1-1024`)
  - Mixed (e.g., `22,80,100-200`)
- 📊 Clean and structured output
- 🧠 Service detection (basic service name resolution)

---

## 🛠️ Technologies Used

- **C**
- **libpcap** (packet capture)
- **pthread** (multithreading)
- **Makefile**

---

## 📦 Installation

```bash
git clone https://github.com/your-username/ft_nmap.git
cd ft_nmap
make
```

---

## ▶️ Usage

```
./ft_nmap [OPTIONS]
```

### Options:

| Option | Description |
| --- | --- |
| `--help` | Show help menu |
| `--ip` | Target IP address |
| `--file` | File containing list of IPs |
| `--ports` | Ports to scan (e.g., `1-100`, `22,80`) |
| `--speedup` | Number of threads (max: 250) |
| `--scan` | Scan type(s) |

---

## 💡 Examples

### Scan a single IP with SYN scan:

```
./ft_nmap--ip192.168.1.1--ports20-80--scan SYN--speedup50
```

### Scan multiple scan types:

```
./ft_nmap--ip192.168.1.1--ports1-1024
```

### Scan from file:

```
./ft_nmap--file targets.txt--ports80,443--scan SYN ACK
```

---

## 📊 Output Example

```
Scan Configurations
Target Ip-Address : x.x.x.x
No of Ports to scan : 20
Scans to be performed : SYN
No of threads : 70

Scanning...
...

Open ports:
Port    Service   Result
80      http      Open
```

---

## 🧠 What I Learned

- Low-level network programming
- Packet crafting and analysis
- Multithreading optimization
- Performance vs accuracy trade-offs in scanning
- Working with `libpcap` and raw sockets

---

## ⚠️ Disclaimer

This tool is developed for **educational purposes only**.

Do not use it on networks or systems without proper authorization.

---

## 👨‍💻 Author

- Mohammed Annahri

---

## 📄 License

This project is for academic use (1337 School project).