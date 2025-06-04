![Screenshot 2025-06-04 204216](https://github.com/user-attachments/assets/73710db5-69aa-4b4a-86ad-a95fd00c4839)# 🧪 [CTF] Dridex Malware Infection Analysis - SOC Challenge

**Date Completed:** June 4, 2025  
**Role Simulated:** SOC Analyst  
**Scenario:**  
An internal host in the Umbrella Corporation triggered a SIEM alert for contacting a known malicious domain. A PCAP was retrieved for further investigation.

---

## 🧠 Challenge Questions & Answers

**1. What’s the private IP of the infected host?**  
`10[.]11[.]27[.]101`  
*Identified via DNS requests and consistent outbound HTTP traffic.*

**2. What’s the malware binary that the macro document is trying to retrieve?**  
`spet10.spr`  
*Observed in an HTTP GET request containing 'MZ' header – indicates a PE executable.*

**3. From what domain are HTTP requests with GET /images/ coming from?**  
`cochrimato[.]com`  
*Seen in a GET request leading to a `.avi` file. Domain confirmed as malicious via VirusTotal.*

**4. What’s the full URL ending in .rar where Ursnif retrieves the follow-up malware from?**  
`http:///95[.]181[.]198.231/: oiioiashdqbwe[.]com.rar`  
*Extracted from an HTTP GET request from the infected host.*

**5. What is the Dridex post-infection traffic IP address beginning with 185.?**  
`: 185[].244[.]150[.]230`  
*Observed in encrypted TLSv1.2 traffic; confirmed by ET MALWARE alert for Dridex SSL Certificate.*

---

## 🔍 Investigation Steps

1. **Initial Traffic Analysis**  
   - Opened PCAP in Wireshark
   - Used `Statistics > Conversations` and `Protocol Hierarchy` to identify talkative hosts.

2. **DNS Analysis**  
   - Filtered with `dns` and noted queries made by the internal IP.
   - Resolved domains were investigated via VirusTotal.

3. **HTTP Traffic**  
   - Used `http.request` and followed TCP streams.
   - Identified download of a suspicious `.spr` executable and a `.rar` file.

4. **TLS/SNI Analysis**  
   - Filtered with `ssl.handshake.extensions_server_name` to find SNI domains.
   - Flagged suspicious IPs with Russian geolocation.

5. **Zui (Zeek) Threat Detection**  
   - Loaded PCAP into Zui
   - Queried for `alerts` and found:
     - **ET MALWARE ABUSE.CH SSL Blacklist (Dridex)** alert
     - SSL cert used for C2 traffic

6. **Artifact Extraction**  
   - Exported all HTTP objects
   - Used `file *` command to identify PE files
   - Verified hashes with VirusTotal

---

## 💡 Key Takeaways

- 📌 Email attachments with macros remain a primary initial access vector.
- 🧠 Always correlate PCAP artifacts with threat intelligence (VT, alerts).
- 🔐 C2 communication can occur over encrypted channels, but SSL SNI leaks context.
- 📁 Use tools like Zui/Zeek to enrich packet-level data.

---

## 🛠️ Tools Used

- Wireshark  
- VirusTotal  
- Zui (Zeek UI)  
- `file`, `sha256sum`, Linux CLI

---

## 📸 Screenshots (Optional)
![Screenshot 2025-06-04 203738](https://github.com/user-attachments/assets/32e9c491-2eee-4fe5-bbe6-8ab4fe0c21df)
![Screenshot 2025-06-04 223618](https://github.com/user-attachments/assets/b69aeb3d-de73-47e5-bd04-4b7f54ea5b71)
![Screenshot 2025-06-04 203835](https://github.com/user-attachments/assets/3aadf722-90e4-479f-8956-50c3afabb55e)
![Screenshot 2025-06-04 203909](https://github.com/user-attachments/assets/57ca1320-8791-4978-ab42-09f35cd0d960)

![Screenshot 2025-06-04 213734](https://github.com/user-attachments/assets/1b34a246-f4d1-47d8-83bc-39d68aa35eda)

![Screenshot 2025-06-04 213707](https://github.com/user-attachments/assets/7b13656f-f449-4812-a0bb-675625c19708)

---

## 🚨 Disclaimer
This analysis was done for educational purposes in a controlled lab environment.
