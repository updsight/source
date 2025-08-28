# When Updates Backfire: A Black-Box Security Analysis of Desktop Software Update Mechanisms

## Abstract

Desktop software has become an essential component of modern computing, and software updates are the primary mechanism to patch vulnerabilities and deliver security fixes. However, the update process itself introduces new attack surfaces, particularly when validation of update data is incomplete or improperly enforced. Nevertheless, these risks in desktop updates are less studied because most update clients are closed-source and complex.

We present Updsight, a black-box framework that tests update security by simulating MitM attacks in realistic settings. Updsight operates by emulating man-in-the-middle scenarios, intercepting traffic during the update process, and automatically validating the presence of critical weaknesses. By combining traffic interception, payload integrity inspection, and behavior monitoring, Updsight provides a comprehensive assessment of update trust models across diverse software categories.

We adopted Updsight to 120 widely-used desktop applications. The results show 20 exploitable vulnerabilities, including downgrade, manifest manipulation, installer hijack, and path traversal. Among these, 9 have been confirmed by vendors, and 4 are in the process of receiving CVEs.

Our findings highlight recurring design flaws, such as unsigned manifests and weak rollback checks, which allow attackers to gain code execution through the update channel.


# Evaluation Workflow Overview

This section outlines the three-phase experimental procedure designed to detect and validate vulnerabilities in Windows software update mechanisms, including setup, traffic interception, and exploit verification.

---

## 1. Update-Initiator (Inside VM)

This phase is conducted inside a virtual machine (VM):

- **Proxy Configuration**: The system-wide proxy is set to the host machine’s IP address and port `8888`, allowing all outbound traffic to be intercepted on the host.
- **Automated Installation**: Applications are installed using [Chocolatey](https://chocolatey.org/) or manual installers. Most installations default to `Program Files`, and the `Update-Initiator.py` is placed one directory above the installation path.
- **Triggering Updates**: `python Update-Initiator.py` automatically scans for newly added executables, system services, and scheduled tasks. It attempts to launch these components to trigger post-installation updates or background downloads.

---

## 2. Domain-Tracer, MitM-Insight and Response-Crafter (On Host)

This phase is run on the host machine:

- **DNS Hijacking Simulation**: Run `python Domain-Tracer.py` to simulate DNS redirection by spoofing domain resolutions. A whitelist file `allowed_hosts.txt` is used to exclude certain domains (e.g., `chocolatey.org`) from redirection.
- **HTTP/HTTPS Proxy Setup**: Run `fake80.exe` and `fake443.exe` to act as transparent MITM proxies for HTTP and HTTPS traffic respectively. These tools log intercepted traffic into `http.txt` and `https.txt`, see if the software violates rule R1, validate transport security, and save original update payloads to the `download/` folder.
- **Automated Payload Replacement**:
  - Based on MIME-type detection, intercepted files are matched to replacements under the `fake/` directory (e.g., `1.zip`, `1.exe`, `1.7z`).
  - If no match is found, the original intercepted file from `download/` is returned.
  - Manual editing of files in `download/` is also supported for fine-grained tampering, check here if the software violates rule R2.

---

## 3. Exploit-Validator (Inside VM)

This phase is executed inside the virtual machine:

- **Execution Detection**: `python Exploit-Validator.py` monitors the system to check whether a forged `.exe` file (specified via its MD5 hash) was executed. A successful execution indicates a remote code execution (RCE) vulnerability.
- **Path Traversal Detection**: The tool also monitors extraction behavior. If multiple instances of `cve.txt` appear in different directories, it flags a **path traversal attack** (normally, only one such file should be extracted).
- **Result Logging and Inference**: All results are logged and summarized, with rule violations (R3–R4) inferred based on execution evidence.
"""
