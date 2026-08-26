# Samama-network-forensics-suite
#  Tactical Defensive Network Forensics & Cryptanalytic Intelligence Suite

An elite, multi-modular passive network monitoring ecosystem, high-performance intrusion detection architecture, and traffic metadata profiling suite written entirely from scratch in Python. Operating statefully across 8,800+ lines of custom production-grade logic, this framework maps bidirectional packet integrity streams, parses complex network layers, and intercepts traffic anomalies using mathematical behavioral baselines.

---

##  Detailed File Architecture & Component Matrix

The entire framework is divided into high-performance atomic modules mapped according to standard security software engineering structures:

###  1. `Checking_man_in_midle_attack_detector.py` (3,248 Lines)
- **Purpose**: Deep Packet Inspection (DPI) & Flow State Machine.
- **Core Logic**: This is the core protocol verification engine. It programmatically intercepts live network streams to mathematically track active TCP sequence numbers (`seq` / `ack`). By preserving a rigid state table, it dynamically targets, flags, and blocks Man-in-the-Middle (MitM) payload injections, packet drops, or live segment data replacement.

###  2. `start1.py` (3,105 Lines)
- **Purpose**: Master Orchestrator, Analytics Engine & Interactive HTML Core.
- **Core Logic**: Operates as the central driver and telemetry logging system. It parses raw connection pools, aggregates multi-tiered anomalies, and generates comprehensive human-readable summary files, standalone raw JSON dumps, and rich, highly interactive HTML forensic report dashboards.

###  3. `pcap_organizer.py` (1,219 Lines)
- **Purpose**: Binary Input Aggregator, Filtering Router & CLI Parser.
- **Core Logic**: Handles structural execution orchestration. It aggregates, filters, and formats raw input parameter paths and files. This module cleans up execution arrays before pipelining raw network blocks directly into the respective asynchronous tracking worker queues.

###  4. `location_finder_on_both_ends_server_and_client.py` (1,228 Lines)
- **Purpose**: Autonomous System Tracking, Geolocation, & Proxy Profiler.
- **Core Logic**: Serves as the central Threat Intelligence parsing layer. It evaluates external public network nodes to resolve Autonomous System Numbers (ASN), ISP backbones, and organizational metadata while detecting obfuscation parameters such as VPN exit gateways, active Tor networks, or underlying data center hosting blocks.

###  5. `finding_p_g_using_hex_decoder.py`
- **Purpose**: High-Precision Big-Integer Mathematical Decoder.
- **Core Logic**: An isolated cryptographic arithmetic framework. It decodes massive hexadecimal configurations captured directly from network streams into high-precision, arbitrary big-integer structures using native multi-precision arithmetic. This prepares dynamic inputs (primes, generators, and point allocations) to feed backend crypto-breaking and optimization modules.

---

##  Key Intelligence & Forensics Capabilities

- **Stateful 5-Tuple Connection Aggregator**: Merges asymmetrical traffic chunks into fully managed bi-directional network flow instances (`FlowState`).
- **Mathematical Delay Forensics**: Employs continuous Z-Score calculation based on population standard deviation metrics to spot network delays, micro-stuttering, or malicious channel degradation.
- **Deep Sequence Tampering Interception**: Tracks shifting TCP sequence pointers alongside dynamic cryptographic payload SHA-256 validation to pinpoint active data modification attempts.
- **Cognitive Threat Intelligence Engine**: Evaluates public endpoints, resolving geographic attribution via an asynchronous LRU-cached intelligence API.
- **Client Fingerprinting Heuristics**: Analyzes protocol signatures, matching TLS Application-Layer Protocol Negotiation (ALPN) metrics and HTTP User-Agent variables to construct browser profiles without decrypting packet data.

---

##  System Operational Blueprint

### Standalone Tactical Threat Intel Lookup
```bash
python location_finder_on_both_ends_server_and_client.py --ip 8.8.8.8
```

### Deep Criminal Packet Forensics Processing Execution
```bash
python start1.py network_dump.pcapng
```

---
*Disclaimer: This architecture is engineered strictly for passive, non-intrusive structural auditing and cryptographic digital forensics research.*
