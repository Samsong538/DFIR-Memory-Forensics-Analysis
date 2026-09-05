# DFIR Writeup: Memory Forensic Analysis of Corrupted Kali Linux Image

Challenge Name: Corrupted Kali Memory Analysis

Category: Digital Forensics & Incident Response (DFIR) / Memory Forensics

Target File: kali_memory.lime

Difficulty: Hard

Status: Completed

## Executive Summary

During a digital forensics investigation of a Kali Linux memory dump (kali_memory.lime), standard automated analysis using Volatility 3 failed due to kernel layer translation errors. By pivoting to manual physical memory carving, byte-offset tracking, and string extraction, critical forensic artifacts were successfully recovered. The analysis uncovered adversary shell history, targeted network infrastructure, tool executions, and the primary base64-encoded credential string inside pass.txt.

## 1. Initial Triage & Technical Obstacles

Initial attempts to parse kali_memory.lime using standard Volatility 3 Linux plugins (linux.pslist, linux.bash) resulted in symbol translation failures and address space errors.

* **Root Cause:** The RAM dump contained dual kernel banner artifacts (6.1.0-15-kali-amd64 and 7.1.5), which corrupted virtual-to-physical address translation tables within Volatility's automated framework.
* **Pivoting Strategy:** Abandoned automated virtual memory translation plugins in favor of raw physical memory carving, string extraction, and byte-offset analysis using strings, grep, dd, and xxd.

## 2. Investigation & Artifact Recovery

### Phase 1: Reconstructing Shell History & Process Activity

Searching for active process handles and shell activity revealed prior execution logs for PID 4188 (pid.4188.*.dmp), alongside interactive terminal commands.

Key commands identified in RAM buffers:

```
echo 'rule MaliciousBase64 { strings: $a = "aGVsbG8" condition: $a }' > rule.yar
strings -e l pid.4188.*.dmp | grep -i "aGVsbG8"
cat pass.txt
```

### Phase 2: Locating Physical Byte Offsets

To extract the actual contents of pass.txt and inspect heap allocations surrounding PID 4188, physical byte offsets were extracted from the .lime file:

```
grep -a -b -o "pass.txt" ~/dfir_lab/kali_memory.lime
```

### Phase 3: Phase 3: Raw Memory Carving

Using dd and xxd, raw memory blocks were carved around offset 408282690 and payload string offset 534836115:

```
dd if=~/dfir_lab/kali_memory.lime bs=1 skip=534836115 count=512 2>/dev/null | xxd
```

The resulting hexdump revealed the raw payload string aGVsbG8 stored directly within shell environment variables and heap buffers.

## 3. Decryption & Artifact Synthesis

Decoding the extracted string confirmed the cleartext payload:

```
echo "aGVsbG8=" | base64 -d
# Output: hello
```

### Key Extracted Artifacts

| **Artifact Category** | **Extracted Data / Value** | **Forensic Context** |
| :--- | :--- | :--- |
| Primary Credential | aGVsbG8= | Found in pass.txt buffers; decodes to hello |
| Targeted Process | PID 4188 | Suspicious process targeted for memory dumping |
| YARA Rule Target | rule.yar | YARA rule MaliciousBase64 matching string aGVsbG8= |
| Target Infrastructure | rdp://192.168.7.131 | Remote desktop connection target found in memory buffers |
| Reconnaissance Tools | feroxbuster, hydra | Identifiers found via .hydra.restore and command execution flags |
| Kernel Version | 6.1.0-15-kali-amd64 | Primary active kernel build structure recovered from RAM |


## 4. Conclusion & Key Takeaways

1. Automation Resilience: When memory structure corruption breaks automated Volatility symbol layers, manual physical carving (grep -a -b -o + dd + xxd) remains an effective fallback method for recovering key artifacts.
2. Artifact Persistence: Interactive shell commands, file path buffers, and stdout outputs persist within heap memory allocations long after process execution finishes.
