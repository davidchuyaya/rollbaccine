import subprocess
import csv
import os
import json

# Function to run fio command with sudo and return its output
def run_fio(job_name, write_mode, io_type, direct, runtime, filename):
    command = [
        "sudo",  # Ensure sudo is a separate argument
        "fio",
        "--name", job_name,
        "--rw", write_mode,
        "--direct", str(direct),
        "--bs", "4k",             # Block size of 4KB
        "--runtime", str(runtime),  # Number of loops
        "--filename", filename,    # The disk or file to run the test on
        "--output-format", "json"
    ]
    
    print(f"Running fio command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Error running fio: {result.stderr}")
        return None
    return json.loads(result.stdout)

# Function to save the result to a CSV file
def save_to_csv(job_name, result, output_file):
    # Extract relevant performance data from fio output
    jobs = result.get("jobs", [])
    if not jobs:
        print(f"No jobs found in fio output")
        return
    
    with open(output_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        for job in jobs:
            row = [
                job_name,
                job["jobname"],
                job["read"]["iops"],
                job["read"]["bw"],
                job["read"]["lat_ns"]["mean"],
                job["write"]["iops"],
                job["write"]["bw"],
                job["write"]["lat_ns"]["mean"]
            ]
            writer.writerow(row)

# Function to get valid input from user
def get_valid_input(prompt, options):
    while True:
        print(prompt)
        for key, value in options.items():
            print(f"{key}: {value}")
        choice = input("Enter your choice: ")
        if choice in options:
            return options[choice]
        print("Invalid choice, please try again.")

# Function to get valid integer input
def get_valid_int_input(prompt):
    while True:
        try:
            value = int(input(prompt))
            return value
        except ValueError:
            print("Invalid input, please enter an integer.")

# Function to get user input interactively with options
def get_user_input():
    # Job name
    job_name = input("Enter job name: ")

    # Write mode options
    write_modes = {
        "1": "write",
        "2": "read",
        "3": "randwrite",
        "4": "randread"
    }
    write_mode = get_valid_input("Select write mode:", write_modes)

    # Direct I/O options
    direct_options = {
        "1": 1,  # Direct I/O
        "2": 0   # Buffered I/O
    }
    direct = get_valid_input("Direct I/O (bypass cache)?", direct_options)

    # Number of loops
    runtime = get_valid_int_input("Enter runtime: ")

    # Disk or filename
    filename = input("Enter the disk or file path (e.g., /dev/mapper/encryption): ")

    # Output CSV file
    output_file = input("Enter output CSV file name (default: fio_results.csv): ") or "fio_results.csv"

    return job_name, write_mode, direct, runtime, filename, output_file

def main():
    job_name, write_mode, direct, runtime, filename, output_file = get_user_input()
    
    if not os.path.exists(output_file):
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Job Name", "FIO Job", "Read IOPS", "Read Bandwidth (KB/s)", "Read Latency (ns)", 
                             "Write IOPS", "Write Bandwidth (KB/s)", "Write Latency (ns)"])
    
    # Run fio with the specified arguments
    fio_result = run_fio(job_name, write_mode, write_mode, direct, runtime, filename)
    
    if fio_result:
        save_to_csv(job_name, fio_result, output_file)
        print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()