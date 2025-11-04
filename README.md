# Huntress CTF 2025 — 30-Day Capture The Flag

This CTF is the third annual event hosted by Huntress and provides daily challenges across **malware analysis, forensics, reverse engineering, OSINT, binary exploitation, and incident response.**

This repository documents my overall approach, tools, workflow, and skills demonstrated during the entire month-long event.

## Objective
Strengthen real-world defensive cybersecurity and investigative skills by completing daily hands-on challenges using deployed virtual machines, malware samples, PCAPs, executables, OSINT trails, Windows/Linux forensics, and remote exploitation tasks.

**This event focused on:**
- Malware reverse engineering
- Incident response & triage
- Forensics (host, memory, and filesystem)
- Network traffic analysis
- Binary exploitation
- OSINT investigations
- Web & cloud application analysis
- Threat hunting & detection engineering

## Skills Learned
Through the 31-day challenge, I strengthened the following skills:
- Static & dynamic malware analysis (PE files, obfuscated scripts, droppers, phishing kits)
- Windows & Linux forensics (Recycle Bin, metadata, file recovery, registry artifacts)
- Network/PCAP analysis: protocol inspection, stream reconstruction, anomaly detection
- Reverse engineering: Ghidra, IDA, CyberChef, deobfuscation, Nim RE basics
- Binary exploitation using netcat and custom payload crafting
- OSINT research & attribution techniques (Follow The Money 1 & 2)
- Triage workflows for MDR/XDR alerting
- Secure VM isolation, VPN connectivity, and remote RDP/SSH investigation
- Identifying data exfiltration & malicious infrastructure
- Solving CrackMe challenges and PowerShell/JavaScript deobfuscation
- Real-world IR thinking: timeline analysis, root-cause review, threat-actor behavior

## Tools Used
Below are the primary tools and platforms I used throughout the CTF:
- Forensics & Analysis
- Autopsy / Sleuth Kit
- Volatility / Volatility3
- Exiftool
- FTK Imager
- CyberChef

**Malware & Reversing**
- Ghidra
- IDA Free
- x64dbg / WinDbg
- Sysinternals Suite (ProcMon, Autoruns, Process Explorer)
- PEview / Detect It Easy (DIE)
- Radare2 / strings / binwalk

**Networking**
- Wireshark / tcpdump
- Netcat (nc)
- OpenVPN
- Burp Suite (when applicable)

**Scripting & CLI Tools**
- PowerShell
- Python (requests, base64, custom scripts)
- Bash utilities (grep, sed, awk, jq, curl)

**Platforms**
- CourseStack browser-based virtual machines
- Local isolated VMs (Windows + Linux)
- Git, VS Code, and markdown tooling

## Steps / Workflow
**1. Read the Challenge Prompt**
- Identify the objective, file types, passwords, and category (malware, binary, OSINT, etc.)
- Review warnings (especially malware challenges requiring isolation).

**2. Prepare an Isolated Analysis Environment**
- Use snapshots in VirtualBox/VMware
- Disable networking for malware unless required
- Load VM tools and configure folder isolation

**3. Obtain the Artifact or Launch VM**
- Extract ZIPs (passwords provided)
- Deploy CourseStack VMs and connect via RDP, SSH, or browser console
- Establish VPN for direct access when necessary

**4. Initial Triage**
- Run: file, strings, hashing, metadata review
- Categorize the challenge (script, binary, pcap, OSINT, IR triage, etc.)

**5. Static Analysis**
- Inspect suspicious files (Ghidra, IDA, DIE, CyberChef, deobfuscation)
- Review imports, strings, embedded payloads, encryption indicators

**6. Dynamic Analysis (when safe)**
- Execute in isolated VM
- Monitor behavior with ProcMon, netstat, Wireshark, Autoruns
- Observe file writes, registry changes, and network connections

**7. Network Forensics**
- Analyze PCAPs for suspicious flows
- Extract files, decode protocols, identify C2 or exfiltration
- Follow TCP streams or reassemble payloads

**8. Reverse Engineering / Exploitation**
- Debug binaries, identify logic flaws, patch or bypass conditions
- Connect to remote exploitation challenges via netcat
- For CrackMe-style tasks, step through execution flow

**9. OSINT & Attribution (Follow the Money challenges)**
- Use only public records
- Review usernames, aliases, domains, and external artifacts
- Map indicators to publicly available data

**10. Recover the Flag**
- Extract or reconstruct the final flag
- Validate the output format (some challenges used non-standard flags)

**11. Document Findings**
- Markdown notes
- Steps taken
- Tools used
- Successful commands

**12. Clean Up**
- Revert VM snapshot
- Clear malicious files
- Reset environment for the next challenge

## High-Level Summary of the 31-Day Challenge
- **Malware Analysis:** Investigating obfuscated scripts, droppers, Chrome extension malware, phishing kits, PowerShell malware, and credential stealers.
- **Forensics:** Windows Recycle Bin artifacts, timeline reconstruction, deleted data recovery, encrypted file analysis, crashed VM backups.
- **Reverse Engineering:** EXEs built in Nim, CrackMe logic puzzles, hash reconstruction, embedded payload extraction.
- **Network/PCAP Analysis:** ICS bus traffic capture, exfiltration flows, strange HMI messages, packet-level investigation.
- **Binary Exploitation:** Remote service interaction (netcat), buffer manipulation, CTF-style binary challenges.
- **OSINT:** Attribution, tracing fraudulent money transfers, researching threat-actor identifiers.
- **Incident Response:** Analyzing alerts from an XDR/MDR tool, reviewing suspicious scripts, correlating events.
- **Miscellaneous:** Web exploitation, credential issues, misconfigured applications, tricky logic puzzles.
