import os
import urllib.request
import zipfile
import json
import shutil
from pathlib import Path

# Paths
DATA_DIR = Path(__file__).parent / "practice"
ADFA_LD_URL = "https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset/archive/refs/heads/master.zip"
LID_DS_URL = "https://github.com/LID-DS/LID-DS/archive/refs/heads/master.zip"

def download_and_extract(url, extract_to):
    print(f"Downloading {url}...")
    zip_path = extract_to / "temp.zip"
    
    # Add a user-agent to avoid 403 Forbidden on some GitHub endpoints
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response, open(zip_path, 'wb') as out_file:
        shutil.copyfileobj(response, out_file)
        
    print(f"Extracting {zip_path}...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
        
    os.remove(zip_path)
    print("Extracted.")

def parse_adfa_ld_to_syscall_records(extracted_dir):
    print("Parsing ADFA-LD to SyscallRecords...")
    adfa_dir = extracted_dir / "a-labelled-version-of-the-ADFA-LD-dataset-master"
    out_dir = DATA_DIR / "ADFA-LD_SyscallRecords"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # We will search for all .txt files which contain space-separated syscall numbers
    for txt_file in adfa_dir.rglob("*.txt"):
        if txt_file.name == "readme.txt":
            continue
            
        with open(txt_file, 'r') as f:
            content = f.read().strip()
            
        if not content:
            continue
            
        syscalls = content.split()
        
        # Determine category based on path
        category = "normal" if "Training_Data_Master" in str(txt_file) or "Validation_Data_Master" in str(txt_file) else "attack"
        
        out_file = out_dir / (txt_file.stem + ".jsonl")
        
        with open(out_file, 'w') as out_f:
            # Note: ADFA-LD doesn't have timestamps, PIDs, or arguments. 
            # We mock these to fit the SyscallRecord format.
            for i, syscall_num in enumerate(syscalls):
                record = {
                    "timestamp": float(i),  # Mock timestamp based on sequence
                    "pid": 1000,            # Mock PID
                    "uid": 1000,            # Mock UID
                    "comm": category,       # Using comm to store the category
                    "syscall": str(syscall_num),
                    "args": {}              # No arguments available
                }
                out_f.write(json.dumps(record) + "\n")
                
    print(f"Parsed ADFA-LD to {out_dir}")

def parse_lid_ds_to_syscall_records(extracted_dir):
    print("Parsing LID-DS to SyscallRecords...")
    lid_dir = extracted_dir / "LID-DS-master"
    out_dir = DATA_DIR / "LID-DS_SyscallRecords"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # LID-DS has a specific JSON format or raw logs.
    # Since the full LID-DS dataset files are extremely large and typically hosted on Zenodo or require 
    # the LID-DS dataloader to download, this script sets up the repository structure and 
    # creates a placeholder SyscallRecord if no raw trace files are found in the immediate zip.
    
    # Let's see if we can find any .json or .txt traces to parse.
    found_traces = False
    for trace_file in lid_dir.rglob("*.json"):
        if "package.json" in trace_file.name: continue
        # Simplified parsing if it happens to be an auditd or similar log
        # For now, we just copy or acknowledge it
        found_traces = True
        
    if not found_traces:
        print("Note: Actual LID-DS trace files are not included in the main GitHub repository zip.")
        print("You will need to use the LID-DS scripts to download the full dataset (~100GB+).")
        print("Creating a sample SyscallRecord for demonstration...")
        
        sample_file = out_dir / "lid_ds_sample.jsonl"
        with open(sample_file, 'w') as out_f:
            record = {
                "timestamp": 1600000000.0,
                "pid": 2000,
                "uid": 0,
                "comm": "sample_lid_ds_proc",
                "syscall": "execve",
                "args": {"filename": "/bin/ls"}
            }
            out_f.write(json.dumps(record) + "\n")
            
    print(f"LID-DS setup complete in {out_dir}")

def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # 1. ADFA-LD
    adfa_extract_dir = DATA_DIR / "raw_adfa_ld"
    adfa_extract_dir.mkdir(exist_ok=True)
    download_and_extract(ADFA_LD_URL, adfa_extract_dir)
    parse_adfa_ld_to_syscall_records(adfa_extract_dir)
    
    # 2. LID-DS
    lid_extract_dir = DATA_DIR / "raw_lid_ds"
    lid_extract_dir.mkdir(exist_ok=True)
    download_and_extract(LID_DS_URL, lid_extract_dir)
    parse_lid_ds_to_syscall_records(lid_extract_dir)
    
    print("\nDataset download and setup is complete!")

if __name__ == "__main__":
    main()
