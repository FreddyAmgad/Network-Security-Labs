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

## 📘 Lab 2 Summary: ARP Cache Poisoning & MITM Attacks

In this lab, I successfully completed all tasks assigned in the **AUC CyberRange Network Security Lab** focused on ARP cache poisoning and Man-In-The-Middle (MITM) attacks. The exercises were conducted using Scapy to explore the mechanisms behind spoofing and traffic manipulation in local networks.

---

### 🧪 Task 1.A: ARP Request Poisoning

I initiated an ARP **request** from the attacker (Host M) to Host A, claiming to be Host B but providing M’s MAC address:
- This fooled A into updating its ARP cache, associating B’s IP with M’s MAC.
- Demonstrated how attackers can inject false ARP mappings even using a *request* packet.

This task showed how ARP request poisoning can be just as effective as replies in manipulating network behavior.

---

### 🧪 Task 1.B: ARP Reply Poisoning

I crafted and sent a forged ARP **reply** to Host A, stating:
- “I am Host B, and my MAC address is (M’s MAC).”

Two scenarios were tested:
1. **When Host A already had B’s IP in cache** — the spoofed reply updated the MAC mapping.
2. **When Host A did not have B’s IP in cache** — the spoofed reply added a new entry.

This demonstrated how ARP replies are blindly accepted on local networks, making spoofing a trivial process for an attacker.

---

### 🔄 Task 2.A: MITM Attack (No Forwarding)

In this task, I:
- Poisoned both A and B to route traffic through M.
- **Did not enable IP forwarding** on the attacker machine.

As a result, packets reached M but were dropped, simulating a DoS-like condition. This task highlighted how interception without packet relaying halts communication.

---

### 🔁 Task 2.B: MITM with Forwarding Enabled

Using the same ARP poisoning strategy, I:
- Enabled IP forwarding on M with `sysctl -w net.ipv4.ip_forward=1`.
- Successfully relayed packets between A and B.

This allowed me to observe and manipulate traffic transparently. It demonstrated how MITM attackers can intercept and forward traffic without disrupting communication.

---

### 🧬 Task 2.C: Telnet Interception and Spoofing

In the final task, I:
- Sniffed Telnet traffic (TCP port 23) after ARP poisoning.
- Spoofed packets to alter communication by replacing user input with the character `'Z'`.

By intercepting and modifying Telnet keystrokes in real time, this task illustrated the vulnerability of plaintext protocols to content manipulation during MITM attacks.

---

## 💡 Takeaways

- ARP lacks authentication, making LANs inherently vulnerable to spoofing.
- MITM attacks are easy to implement once ARP tables are poisoned.
- IP forwarding enables stealthy traffic relaying, crucial for persistent interception.
- Legacy protocols like Telnet are highly insecure due to lack of encryption.

---

