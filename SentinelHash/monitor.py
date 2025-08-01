import os
import hashlib
import json
import argparse
import time
from pathlib import Path
from datetime import datetime
from plyer import notification
from colorama import Fore, Style, init

init(autoreset=True)  # For colored text in terminal

BASELINE_FILE = "baseline.json"
LOG_FILE = "logs.txt"

def compute_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        return f"ERROR: {e}"

def get_all_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for name in filenames:
            full_path = os.path.join(root, name)
            files.append(full_path)
    return files

def create_baseline(path):
    print(Fore.GREEN + f"[+] Creating baseline for: {path}")
    data = {}
    for file in get_all_files(path):
        hash_val = compute_hash(file)
        data[file] = hash_val
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=4)
    print(Fore.GREEN + f"[✓] Baseline saved to {BASELINE_FILE}")

def compare_with_baseline(path, notify=False):
    if not os.path.exists(BASELINE_FILE):
        print(Fore.RED + "[!] No baseline file found. Please create one first.")
        return

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    current_files = get_all_files(path)
    current_hashes = {file: compute_hash(file) for file in current_files}

    added, removed, modified = [], [], []

    for file in baseline:
        if file not in current_hashes:
            removed.append(file)
        elif baseline[file] != current_hashes[file]:
            modified.append(file)

    for file in current_hashes:
        if file not in baseline:
            added.append(file)

    if not added and not removed and not modified:
        print(Fore.CYAN + "[✓] No changes detected.")
    else:
        print(Fore.YELLOW + "[!] Changes detected:")
        if added:
            print(Fore.GREEN + f"   [+] Added: {len(added)}")
        if removed:
            print(Fore.RED + f"   [-] Removed: {len(removed)}")
        if modified:
            print(Fore.YELLOW + f"   [~] Modified: {len(modified)}")
        log_changes(added, removed, modified)
        if notify:
            send_notification(added, removed, modified)

def log_changes(added, removed, modified):
    with open(LOG_FILE, "a") as f:
        f.write(f"\n===== Scan on {datetime.now()} =====\n")
        if added:
            f.write("[+] Added files:\n")
            for file in added:
                f.write(f"    {file}\n")
        if removed:
            f.write("[-] Removed files:\n")
            for file in removed:
                f.write(f"    {file}\n")
        if modified:
            f.write("[~] Modified files:\n")
            for file in modified:
                f.write(f"    {file}\n")
    print(Fore.MAGENTA + f"[+] Changes logged to {LOG_FILE}")

def send_notification(added, removed, modified):
    body = ""
    if added:
        body += f"{len(added)} file(s) added\n"
    if removed:
        body += f"{len(removed)} file(s) removed\n"
    if modified:
        body += f"{len(modified)} file(s) modified"

    notification.notify(
        title="File Integrity Alert",
        message=body,
        timeout=5
    )

def monitor_loop(path, interval):
    print(Fore.CYAN + f"[🔁] Monitoring {path} every {interval} seconds...")
    try:
        while True:
            compare_with_baseline(path, notify=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Monitoring stopped by user.")

def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitoring System")
    parser.add_argument("--baseline", action="store_true", help="Create baseline hash record")
    parser.add_argument("--scan", action="store_true", help="Scan and compare with baseline")
    parser.add_argument("--monitor", action="store_true", help="Start continuous monitoring")
    parser.add_argument("--interval", type=int, default=60, help="Monitoring interval in seconds")
    parser.add_argument("--path", type=str, required=True, help="Target directory path")

    args = parser.parse_args()

    if args.baseline:
        create_baseline(args.path)
    elif args.scan:
        compare_with_baseline(args.path, notify=True)
    elif args.monitor:
        monitor_loop(args.path, args.interval)
    else:
        print(Fore.RED + "[!] Please specify --baseline, --scan, or --monitor")

if __name__ == "__main__":
    main()
