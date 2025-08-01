# SentinelHash
“Sentinel” stands for guardian or watcher, and “Hash” refers to cryptographic hashing — a perfect blend for file monitoring.

SentinelHash
SentinelHash is a lightweight Python-based File Integrity Monitoring System (FIMS) designed to continuously monitor files and directories for unauthorized changes, tampering, or suspicious activity. It uses secure SHA-256 hashing to create a baseline snapshot and compares it to the current state to detect file additions, deletions, or modifications.

Features
Creates a secure SHA-256 hash baseline of files in a directory

Detects added, removed, and modified files by comparing with baseline

Logs all detected changes with timestamps to a log file

Sends desktop notifications on any detected changes

Supports manual scanning and continuous monitoring with customizable intervals

Simple CLI interface with easy-to-understand commands

Color-coded terminal output for easy readability

Requirements
Python 3.7 or above

plyer (for desktop notifications)

colorama (for colored terminal output)

Install dependencies with:

bash
Copy code
pip install plyer colorama
Usage
Run the script with the following command line options:

bash
Copy code
python sentinelhash.py --path <directory_path> [options]
Options
--baseline : Create a baseline snapshot of the directory files and their hashes

--scan : Scan the directory and compare with the baseline to detect changes

--monitor : Start continuous monitoring of the directory for changes

--interval <seconds> : Set the interval (in seconds) for continuous monitoring (default: 60 seconds)

--path <directory_path> : Specify the target directory to monitor (required)

Examples
Create baseline for /home/user/documents:

bash
Copy code
python sentinelhash.py --baseline --path /home/user/documents
Scan and compare current files against the baseline:

bash
Copy code
python sentinelhash.py --scan --path /home/user/documents
Start continuous monitoring every 120 seconds:

bash
Copy code
python sentinelhash.py --monitor --interval 120 --path /home/user/documents
How it Works
Baseline Creation: The program walks through all files in the specified directory, computing a SHA-256 hash for each file. It saves this data as a baseline snapshot (baseline.json).

Scanning: It compares the current state of files against the baseline, detecting files that are added, removed, or modified based on hash differences.

Logging & Notification: Detected changes are logged into logs.txt with timestamps. Desktop notifications alert the user when changes occur.

Monitoring: The monitoring mode runs the scan repeatedly at defined intervals, keeping real-time watch over file integrity.

Notes
The baseline file baseline.json must exist before scanning or monitoring. Create it first using the --baseline option.

The program currently monitors all files recursively under the given directory.

Desktop notifications rely on the plyer library, which supports Windows, macOS, and some Linux desktop environments.

Contributing
Contributions, suggestions, and improvements are welcome! Feel free to open issues or submit pull requests.


