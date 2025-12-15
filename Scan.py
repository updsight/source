import os
import re
import sys

# Default AT1 detection patterns
DEFAULT_PATTERNS = {
    "Cookie": rb"cookie",
    "Email": rb"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Password": rb"password|passwd|pwd",
    "Token": rb"token|authorization|bearer",
}

def build_patterns(user_input=None):
    patterns = {}

    if user_input:
        try:
            patterns["UserInput"] = re.compile(user_input.encode(), re.IGNORECASE)
        except re.error:
            print("[!] Invalid custom pattern")
            sys.exit(1)
    else:
        for name, pat in DEFAULT_PATTERNS.items():
            patterns[name] = re.compile(pat, re.IGNORECASE)

    return patterns

def scan_file(filepath, patterns):
    findings = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
            for name, pattern in patterns.items():
                if pattern.search(data):
                    findings.append(name)
    except Exception:
        pass
    return findings

def main():
    cache_dir = input("[?] Enter cache directory path: ").strip()

    if not cache_dir or not os.path.isdir(cache_dir):
        print("[!] Invalid directory")
        sys.exit(1)

    user_input = input(
        "[?] Enter custom keyword/regex (press Enter to use default rules): "
    ).strip()

    patterns = build_patterns(user_input if user_input else None)

    print(f"\n[+] Scanning directory: {cache_dir}\n")

    for root, _, files in os.walk(cache_dir):
        for file in files:
            path = os.path.join(root, file)
            hits = scan_file(path, patterns)
            if hits:
                print(f"[!] Match found: {path}")
                for h in hits:
                    print(f"    - {h}")
                print()

    print("[+] Scan completed.")

if __name__ == "__main__":
    main()
