# Python DPI Engine - Deep Packet Inspection & Network Analyzer

Yeh document is pure-Python **Deep Packet Inspection (DPI) & Network Analyzer** project ke bare me sab kuch step-by-step explain karta hai — basic networking concepts se lekar complete Python code architecture aur payload parsing tak.

---

## Table of Contents

1. [What is DPI? (Deep Packet Inspection)](#1-what-is-dpi-deep-packet-inspection)
2. [Networking Background (OSI & Network Stack)](#2-networking-background-osi--network-stack)
3. [Project Architecture & Overview](#3-project-architecture--overview)
4. [File Structure](#4-file-structure)
5. [Step-by-Step Packet Journey in Python](#5-step-by-step-packet-journey-in-python)
6. [Deep Dive: Har Python Component Ka Analysis](#6-deep-dive-har-python-component-ka-analysis)
   - [PcapReader (pcap_reader.py)](#step-1-pcap-reading-pcap_readerpy)
   - [PacketParser (packet_parser.py)](#step-2-protocol-parsing-packet_parserpy)
   - [ProtocolInspector (sni_extractor.py)](#step-3-sni-http--dns-inspection-sni_extractorpy)
   - [ConnectionTracker (connection_tracker.py)](#step-4-5-tuple-stateful-flow-tracking-connection_trackerpy)
   - [RuleManager (rule_manager.py)](#step-5-rule-engine--threat-mitigation-rule_managerpy)
7. [How TLS SNI Extraction Works](#7-how-tls-sni-extraction-works)
8. [How Policy & Blocking Works](#8-how-policy--blocking-works)
9. [Running the Engine](#9-running-the-engine)
10. [Understanding the Dashboard & Terminal Output](#10-understanding-the-dashboard--terminal-output)

---

## 1. What is DPI? (Deep Packet Inspection)

**Deep Packet Inspection (DPI)** ek aisi networking technology hai jo network se guzarne wale har packet ke content aur payload ko deeply examine karti hai. 

Sadharan traditional firewalls sirf packet headers (Layer 3/4 Source/Destination IP aur Port) dekhte hain, jabki **DPI Layer 7 (Application Payload)** ke andar jakar check karta hai.

### Real-World Uses:
- **ISPs**: Heavy bandwidth consumption applications (e.g., BitTorrent) ko identify/throttle karna.
- **Enterprise Security**: Office networks me unauthorized apps ya data exfiltration detect karna.
- **Parental Controls & Content Filters**: Inappropriate ya restricted websites ko filter karna.
- **Cybersecurity / Threat Detection**: Encrypted HTTPS tunnel ke andar domain patterns, crypto miners, aur malware C2 channels pakadna.

### What Our Python DPI Engine Does:
```
User Traffic (PCAP / Live) ──► [Python DPI Engine] ──► Action (ALLOW / ALERT / BLOCK)
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
                 - Identifies Apps             - State Machine
                   (YouTube, Google,             (SYN, ESTABLISHED,
                    Facebook, DNS, HTTP)          CLOSED)
```

---

## 2. Networking Background (OSI & Network Stack)

Jab aap browser me koi website open karte hain, toh data multiple layers se hokar travel karta hai:

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS (SNI), DNS Queries  │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (Reliable), UDP (Fast)    │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IPv4 / IPv6 Addresses         │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ Ethernet Frame (MAC Addrs)    │
└─────────────────────────────────────────────────────────┘
```

### What is SNI (Server Name Indication)?

**Server Name Indication (SNI)** TLS/HTTPS handshake ka ek standard extension hai. Jab aap `https://www.youtube.com` open karte hain:

1. Aapka client (browser) server ko ek **"Client Hello"** message bhejta hai.
2. Kyunki abhi connection encrypt nahi hua hai, yeh message **plaintext** me travel karta hai.
3. Client Hello ke extensions me destination domain name (e.g. `www.youtube.com`) shamil hota hai.

```
TLS Client Hello Structure:
├── Content Type: Handshake (22)
├── Handshake Type: Client Hello (1)
├── Version: TLS 1.2 / 1.3
├── Random: [32 bytes]
├── Session ID & Cipher Suites
└── Extensions:
    └── Server Name Indication (SNI):
        └── Server Name: "www.youtube.com"  ◄── Hum ise binary slice se extract karte hain!
```

---

## 3. Project Architecture & Overview

Yeh project **100% Pure Python** me build kiya gaya hai bina kisi external library ya C-compiler ke jhanjhat ke:

```
┌──────────────────┐
│ .pcap File /     │
│ Raw Bytes Stream │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  PcapReader      │ ──► Reads 24-byte Global Header & 16-byte Packet Headers
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  PacketParser    │ ──► Decodes Ethernet (14B) ──► IPv4 (20B) ──► TCP/UDP (20B/8B)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ ConnectionTracker│ ──► 5-Tuple Key (SrcIP, SrcPort, DstIP, DstPort, Proto)
└────────┬─────────┘     Updates TCP State Machine (SYN_SENT ──► ESTABLISHED)
         │
         ▼
┌──────────────────┐
│ ProtocolInspector│ ──► Inspects Application Payload (TLS SNI / HTTP / DNS)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  RuleManager     │ ──► Evaluates Security Rules & Regex (ALLOW / ALERT / BLOCK)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Real-Time Output │ ──► Terminal Logging & Traffic Statistics Dashboard
└──────────────────┘
```

---

## 4. File Structure

```
packet_analyzer/
├── python/
│   ├── main.py                # Main orchestrator & analytics dashboard
│   ├── packet_parser.py       # Binary packet decoder (struct-based)
│   ├── sni_extractor.py       # DPI inspector for TLS SNI, HTTP & DNS
│   ├── connection_tracker.py  # 5-tuple stateful TCP connection tracker
│   ├── rule_manager.py        # ALLOW / ALERT / BLOCK policy manager
│   └── pcap_reader.py         # Streaming binary .pcap file reader
│
├── test_dpi.pcap              # Real-world network sample capture
├── output.pcap                # Filtered output capture
├── generate_test_pcap.py      # Synthetic traffic generator
└── README.md                  # Complete documentation
```

---

## 5. Step-by-Step Packet Journey in Python

Ek single network packet Python pipeline ke andar kaise process hota hai:

### Step 1: Binary PCAP Reading
`PcapReader` stream se 16-byte ka packet record header aur packet bytes yield karta hai:
```python
reader = PcapReader("test_dpi.pcap")
for timestamp, raw_data in reader.read_packets():
    # raw_data contains the exact raw binary wire bytes
    process_packet(raw_data, timestamp)
```

### Step 2: Protocol Header Parsing
`PacketParser` binary bytes ko standard networking headers me unpack karta hai:
```python
pkt = PacketParser.parse_packet(raw_data, timestamp)

# Parsed fields available:
# pkt.eth.src_mac, pkt.eth.dst_mac
# pkt.ip.src_ip, pkt.ip.dst_ip, pkt.ip.protocol
# pkt.tcp.src_port, pkt.tcp.dst_port, pkt.tcp.flags
# pkt.app_payload (Application Layer Bytes)
```

### Step 3: 5-Tuple Connection Tracking
Flow tracker check karta hai ki kya yeh connection pehle se active hai ya naya session shuru ho raha hai:
```python
flow = conntrack.track_packet(
    src_ip=pkt.ip.src_ip,
    src_p=pkt.tcp.src_port,
    dst_ip=pkt.ip.dst_ip,
    dst_p=pkt.tcp.dst_port,
    proto="TCP",
    length=pkt.raw_length,
    flags=pkt.tcp.flags,
    timestamp=timestamp
)
```

### Step 4: Deep Packet Inspection (DPI)
Payload ko inspect karke Application Protocol aur Domain extract kiya jata hai:
```python
app_res = ProtocolInspector.inspect(pkt.app_payload, src_port, dst_port)
# app_res.protocol -> "TLS", "HTTP", "DNS"
# app_res.domain   -> "www.google.com", "example.com"
```

### Step 5: Security Rule Evaluation
Rule engine domain pattern aur port matching karke action decide karta hai:
```python
action, rule_name = rule_manager.evaluate(
    src_ip=pkt.ip.src_ip,
    dst_ip=pkt.ip.dst_ip,
    src_port=src_port,
    dst_port=dst_port,
    proto="TCP",
    domain=app_res.domain
)
# Returns Action.ALLOW, Action.ALERT, or Action.BLOCK
```

---

## 6. Deep Dive: Har Python Component Ka Analysis

### Step 1: PCAP Reading (`pcap_reader.py`)

Standard PCAP files ka format:
1. **24-byte Global Header**: File format magic number, endianness, aur timestamp resolution define karta hai.
2. **16-byte Packet Header**: Har packet ka timestamp (seconds + microseconds) aur captured length batata hai.

```python
import struct
from typing import Generator, Tuple

class PcapReader:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def read_packets(self) -> Generator[Tuple[float, bytes], None, None]:
        with open(self.filepath, "rb") as f:
            global_header = f.read(24)
            magic = struct.unpack("<I", global_header[:4])[0]
            endian = "<" if magic == 0xA1B2C3D4 else ">"

            while True:
                hdr = f.read(16)
                if len(hdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", hdr)
                packet_data = f.read(incl_len)
                yield ts_sec + (ts_usec * 1e-6), packet_data
```

---

### Step 2: Protocol Parsing (`packet_parser.py`)

Python ke built-in `struct` module ka use karke binary network layers decode hoti hain:

#### 1. Ethernet Header (14 Bytes)
```python
# Destination MAC (6B) + Source MAC (6B) + EtherType (2B)
dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", data[:14])
```

#### 2. IPv4 Header (20 Bytes)
```python
# Version + IHL, TTL, Protocol, Src IP, Dst IP
first_byte = data[0]
ihl = (first_byte & 0x0F) * 4
total_len, _, _, ttl, proto, _ = struct.unpack("!HHHBBH", data[2:12])
src_ip = socket.inet_ntoa(data[12:16])
dst_ip = socket.inet_ntoa(data[16:20])
```

#### 3. TCP Header (20 Bytes)
```python
# Src Port (2B), Dst Port (2B), Seq (4B), Ack (4B), Flags (1B), Window (2B)
src_port, dst_port, seq, ack, offset_res, flags_byte, win = struct.unpack("!HHIIBBH", data[:16])
data_offset = (offset_res >> 4) * 4
flags = {
    "FIN": bool(flags_byte & 0x01),
    "SYN": bool(flags_byte & 0x02),
    "RST": bool(flags_byte & 0x04),
    "ACK": bool(flags_byte & 0x10),
}
```

---

### Step 3: SNI, HTTP & DNS Inspection (`sni_extractor.py`)

Application layer ka payload inspect karne ka logic:

```python
class ProtocolInspector:
    @staticmethod
    def extract_tls_sni(payload: bytes) -> Optional[str]:
        # Check ContentType == Handshake (22) and HandshakeType == ClientHello (1)
        if len(payload) < 43 or payload[0] != 22 or payload[5] != 1:
            return None
        
        # Navigate past SessionID, Cipher Suites, and Compressions to Extensions
        offset = 5 + 4 + 34  # Header + Random
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        
        cipher_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2 + cipher_len
        
        comp_len = payload[offset]
        offset += 1 + comp_len
        
        ext_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2
        
        # Parse Extensions looking for Type 0x0000 (Server Name)
        while offset + 4 <= len(payload):
            ext_type, ext_size = struct.unpack("!HH", payload[offset:offset+4])
            offset += 4
            if ext_type == 0x0000:
                sni_name_len = struct.unpack("!H", payload[offset+3:offset+5])[0]
                return payload[offset+5:offset+5+sni_name_len].decode("utf-8", errors="ignore")
            offset += ext_size
        return None
```

---

### Step 4: 5-Tuple Stateful Flow Tracking (`connection_tracker.py`)

Connections ko identify karne ke liye 5 elements ka key banta hai:
`(Source IP, Source Port, Destination IP, Destination Port, Protocol)`

#### TCP State Machine Implementation:
```python
class TCPState(Enum):
    NONE = "NONE"
    SYN_SENT = "SYN_SENT"
    SYN_RCVD = "SYN_RCVD"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    CLOSED = "CLOSED"
```

1. **Client sends SYN** $\rightarrow$ State: `SYN_SENT`
2. **Server responds SYN-ACK** $\rightarrow$ State: `SYN_RCVD`
3. **Client sends ACK** $\rightarrow$ State: `ESTABLISHED` (Bi-directional data flow)
4. **FIN or RST exchanged** $\rightarrow$ State: `CLOSED`

---

### Step 5: Rule Engine & Threat Mitigation (`rule_manager.py`)

Rule Manager inspect kiye gaye domains aur connection parameters par security actions enforce karta hai:

```python
class Action(Enum):
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    BLOCK = "BLOCK"

# Default Security Signatures:
# 1. Block Tor Network (.onion domains)
# 2. Alert on Crypto Mining traffic (pool/mine/stratum patterns)
# 3. Alert on unencrypted Telnet sessions (Port 23)
# 4. Alert on high-entropy DNS Tunneling queries
```

---

## 7. How TLS SNI Extraction Works

HTTPS traffic encrypt hone se pehle SNI extension exchange hota hai. Binary offset breakdown:

```
+-------------------------------------------------------------+
| TLS Record Header (5 Bytes)                                 |
| Type: 0x16 (Handshake) | Version: 0x0303 | Length: 0x01FC   |
+-------------------------------------------------------------+
| Handshake Header (4 Bytes)                                  |
| Type: 0x01 (Client Hello) | Length: 0x01F8                  |
+-------------------------------------------------------------+
| Client Hello Body:                                          |
|  - Client Version (2 Bytes)                                 |
|  - Random (32 Bytes)                                        |
|  - Session ID Length + Data                                 |
|  - Cipher Suites Length + Data                              |
|  - Compression Methods Length + Data                        |
|  - Extensions Length                                        |
|      + Extension: Server Name (0x0000)                      |
|          - Server Name: "www.instagram.com" ◄── EXTRACTED!  |
+-------------------------------------------------------------+
```

---

## 8. How Policy & Blocking Works

DPI Engine har packet par policy apply karta hai:
1. Agar traffic kisi blocked signature (e.g. `.onion` ya restricted domain) se match karta hai $\rightarrow$ Flag as **BLOCK**.
2. Agar suspicious pattern detect hota hai $\rightarrow$ Trigger **ALERT** log with source/destination details.
3. Regular traffic ko pass-through allow karta hai $\rightarrow$ **ALLOW**.

---

## 9. Running the Engine

Kisi bhi external compiler ya additional package install karne ki zaroorat nahi hai:

### 1. Default Sample Analyze Karein:
```bash
python python/main.py
```

### 2. Specific PCAP File Analyze Karein:
```bash
python python/main.py -f test_dpi.pcap
```

---

## 10. Understanding the Dashboard & Terminal Output

Jab aap script run karte hain, real-time live events ke baad full execution statistics milti hain:

```text
[*] Starting analysis of PCAP file: test_dpi.pcap

[DPI] TLS  | 192.168.1.100:54552 -> 142.250.185.206:443   | www.google.com
[DPI] TLS  | 192.168.1.100:58867 -> 142.250.185.110:443   | www.youtube.com
[DPI] TLS  | 192.168.1.100:64044 -> 157.240.1.35:443      | www.facebook.com
[DPI] TLS  | 192.168.1.100:58747 -> 157.240.1.174:443     | www.instagram.com
[DPI] TLS  | 192.168.1.100:55490 -> 140.82.114.4:443      | github.com
[DPI] TLS  | 192.168.1.100:54566 -> 104.16.85.20:443      | discord.com
[DPI] HTTP | 192.168.1.100:58936 -> 93.184.216.34:80       | example.com
[DPI] DNS  | 192.168.1.100:55178 -> 8.8.8.8:53            | www.google.com

=================================================================
       PACKET ANALYZER & DPI ENGINE EXECUTION SUMMARY       
=================================================================
 Total Processed Packets : 77
 Total Processed Volume  : 0.005 MB (5,738 bytes)
 Processing Time         : 0.0016 seconds
 Throughput              : ~48,000+ pkts/sec

------------------------------ Protocol Breakdown ------------------------------
  TCP        : 73       (94.8%)
  UDP        : 4        (5.2%)

------------------------------ Identified DPI Apps ------------------------------
  TLS        : 16       transactions
  HTTP       : 2        transactions
  DNS        : 4        transactions

------------------------------ Active Tracked Flows (27) ------------------------------
  TCP  192.168.1.100:54552 -> 142.250.185.206:443   | Pkts: 4    | State: ESTABLISHED [www.google.com]
  TCP  192.168.1.100:58867 -> 142.250.185.110:443   | Pkts: 4    | State: ESTABLISHED [www.youtube.com]
  TCP  192.168.1.100:55490 -> 140.82.114.4:443      | Pkts: 4    | State: ESTABLISHED [github.com]
=================================================================
```

---

## Summary

Yeh pure Python DPI engine demonstrate karta hai:
1. **Low-level Binary Parsing** without heavy dependencies.
2. **Real-world Application Layer Dissection** (TLS SNI, HTTP, DNS).
3. **Stateful Connection Tracking & Finite State Machines**.
4. **Extensible Security Rules Engine**.
#   D e e p _ P a c k e t - I n s p e c t i o n  
 