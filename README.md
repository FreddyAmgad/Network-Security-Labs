# Network-Security-Labs

## 📘 Lab 1 Summary: Packet Sniffing, Spoofing, and Traceroute

In this lab, I successfully completed all tasks assigned in the **AUC CyberRange Network Security Lab** focused on foundational network security concepts using packet sniffing, spoofing, and traceroute analysis. Here's a breakdown of what I accomplished:

### 🔍 Task 1: Packet Sniffing
I began by passively observing raw traffic across the network using `tcpdump` and `Wireshark`. I then applied advanced filtering techniques to isolate specific traffic types, such as:
- Capturing **only ICMP (ping)** packets.
- Narrowing down to **TCP packets targeting port 23 (Telnet)**.
- Filtering traffic **to and from the local subnet**.
These activities helped me understand how to monitor network behavior and identify protocols of interest under different conditions and user privileges.

### 🛰️ Task 2: Packet Spoofing
In this task, I explored how attackers forge packet headers to impersonate other devices:
- I **crafted packets with spoofed source IPs** using `Scapy`.
- I **sent and captured these packets**, observing how they were received and whether any responses were generated.
- I tested **a variety of spoofed IPs** and analyzed how different spoofing strategies affected detection and network behavior.
This exercise deepened my understanding of trust-based flaws in IP communication and how spoofing can be leveraged in real attacks.

### 🌐 Task 3: Traceroute Analysis
I implemented a **custom traceroute tool using Scapy** to map the path of packets through the network:
- I sent ICMP packets with **increasing TTL values** to observe intermediate hops.
- I analyzed the **Time Exceeded** responses to reconstruct the full route.
- I compared my traceroute results with those from the standard `traceroute` command to validate accuracy and efficiency.
This task enhanced my skills in active reconnaissance and taught me how attackers use TTL manipulation to map internal infrastructure.

---
