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
# Network-Security-Labs

## 📘 Lab 3 Summary: ICMP Redirect Attack and Routing Manipulation

In this lab, I successfully conducted a series of tasks focused on the **ICMP Redirect Attack** within the **AUC CyberRange Network Security Lab** environment. This lab explored how ICMP redirect messages can be exploited by attackers to manipulate the victim's routing cache and perform Man-In-The-Middle (MITM) attacks. Here’s a breakdown of what I accomplished:

---

### 🛰️ Task 1: Launching ICMP Redirect Attack

I began by preparing the victim container to accept ICMP redirect messages, as the default countermeasures in Ubuntu were disabled via the provided `docker-compose.yml` configuration. Then, from the attacker container, I launched the attack by crafting and sending ICMP redirect packets to the victim, targeting the destination **192.168.60.5** and instructing the victim to use **10.9.0.111 (the malicious router)** as the next hop.

Key activities and observations:
- Verified that **`ip route`** did not change the routing table, but the redirect messages **updated the routing cache**.
- Used **`ip route show cache`** to display the updated cache entries after the attack.
- Employed **`mtr -n 192.168.60.5`** to trace the new routing path and confirm that the malicious router was now used as the next hop.

This task solidified my understanding of how ICMP redirects work at the protocol level and how they can be abused to manipulate network routing.

---

### 🌍 Task 1.B: Redirect to a Remote Machine

I adapted the same attack code to target a remote machine outside the local network, specifically the IP address assigned to **usestrix.com**. My observations:
- Although the attack successfully sent redirect packets, it was **not effective** in manipulating the routing of the victim to an external machine due to factors such as **network boundary protections** and the absence of a direct routing path.

This task highlighted the **limitations of ICMP redirect attacks beyond local networks** and how modern routers mitigate these kinds of manipulations.

---

### 🚫 Task 1.C: Redirect to a Non-Existing Machine

Next, I attempted to redirect the victim to a **non-existing machine** within the same network using the same code skeleton. My observations:
- The victim accepted the redirect packets and temporarily updated its routing cache to reflect the fake next hop.
- However, since the destination did not exist, subsequent packet delivery **failed**, resulting in no successful connections or routing beyond the victim’s local cache change.

This task demonstrated the **fragility and temporal nature of routing cache entries** when the next hop is unreachable.

---

### ⚙️ Task 1.D: Analyzing docker-compose.yml Configuration

I reviewed the **docker-compose.yml** file entries specific to the malicious router container. These entries control how the router handles ICMP redirect packets.

Key insights:
- The purpose of these entries is to **enable or disable the sending of ICMP redirects** (`send_redirects` parameter) and allow forwarding behavior (`ip_forward` parameter).
- If their values were changed to **1**, the malicious router would **not send redirect packets** (as it would now behave as a legitimate router), thereby **disabling the attack** in all three cases.

This task provided a deeper understanding of **container-level networking configurations** and their impact on the success of network attacks.

---

## 📘 Lab 4 Summary: TCP Attacks (SYN Flood, Reset, and Session Hijacking)

In this lab, I successfully carried out a series of tasks focused on exploiting TCP protocol vulnerabilities within the **AUC CyberRange Network Security Lab** environment. This lab provided hands-on experience in understanding why certain TCP weaknesses exist, how to exploit them, and why security must be considered from the ground up in protocol design. Here’s a breakdown of my progress:

---

### 🛰️ Task 1: TCP SYN Flooding Attack

A TCP SYN flood attack targets the server’s half-open connection queue, overwhelming it by sending a barrage of spoofed SYN packets.

Key activities and observations:

- Completed a **Python script** to generate and send a large volume of TCP SYN packets with randomized source IPs, ports, and sequence numbers.
- Ran the attack for **at least one minute** to ensure enough impact on the victim’s queue.
- Attempted to connect to the victim’s telnet service to observe the DoS effect.
- On **Ubuntu 20.04**, noticed the TCP cache issue where legitimate connections were still remembered despite the attack.
- Used the **`ip tcp_metrics flush`** command on the victim to remove cached entries, which cleared stale metrics and improved attack effectiveness.

💡 Insights:
- The TCP retransmission behavior (up to 5 retries of SYN+ACKs) meant that multiple concurrent attack instances were required to fully fill the queue.
- Successfully demonstrated how **resource exhaustion** at the TCP level can be exploited to deny legitimate access.

---

### ⚙️ Task 1.B: TCP Cache Issue Mitigation

To address the TCP cache’s impact on SYN flooding:

- Ran the **`ip tcp_metrics flush`** command on the victim.
- Verified that after cache flushing, **no stale entries remained**, making the queue more susceptible to the flood.
- Confirmed that the **attack’s success** was tied to the removal of these cached entries.

---

### ⚙️ Task 1.C: Overcoming TCP Retransmissions

To handle TCP’s resilience:

- Launched **multiple concurrent instances** of the attack script.
- Observed how the extra attack volume was necessary to **override the server’s repeated SYN+ACK retries** and completely exhaust the queue.
- Determined the **number of concurrent attack scripts** needed for a successful SYN flood.

---

### 🚫 Task 2: TCP Reset (RST) Attack

In this task, I forcibly terminated an established telnet session by sending a **forged RST packet** from the attacker to the victim.

Key activities and observations:

- Used **Scapy** to craft spoofed TCP RST packets with **correct 4-tuple values** (source/destination IPs and ports).
- Carefully adjusted the **sequence numbers** based on the sniffed telnet session to ensure a valid RST.
- Successfully disrupted active telnet sessions, showcasing how **TCP’s trust in the 4-tuple** can be exploited to break legitimate connections.

---

### 💣 Task 3: TCP Session Hijacking

In this task, I hijacked an active telnet session by **injecting malicious data** directly into the stream using forged TCP packets.

Key activities and observations:

- Leveraged **Wireshark** to extract the live telnet session’s 4-tuple and current sequence numbers.
- Used **Scapy** to craft and inject TCP packets containing malicious commands into the victim’s telnet session.
- Verified that the victim’s session **executed the injected commands**, illustrating the **critical importance of sequence number protection** in TCP.

---

## 💡 Overall Takeaways

- **TCP’s design**: These attacks highlight how the trust-based design of TCP (e.g., no encryption or strong authentication by default) creates serious vulnerabilities.
- **Mitigations**: Modern systems use measures like **SYN cookies, sequence number randomization, and secure transport protocols (e.g., TLS)** to mitigate these classic attacks.
- **Importance of monitoring**: Tools like **Wireshark** were invaluable for tracking live TCP states and crafting successful attack packets.

---
