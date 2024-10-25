import subprocess
import csv
import os
import json
import paramiko
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from time import sleep

load_dotenv()

username = os.getenv('AZURE_USERNAME')

with open('config.json') as config_file:
    config = json.load(config_file)

for key, value in config.items():
    if isinstance(value, str) and value.startswith("$"):
        env_var = value[1:]
        config[key] = os.getenv(env_var)
    if isinstance(value, str) and "{username}" in value:
        config[key] = value.replace("{username}", username)
# Create the full path

print(config)

SUBSCRIPTION_ID = config['subscription_id']
USERNAME = config['username']
PRIVATE_KEY_PATH = config['ssh_key_path']
SCRIPT_PATH = os.path.join(os.getenv('BASE_PATH'), config['install_script_path'])
RESOURCE_GROUP_NAME = config['resource_group_name']

compute_client = ComputeManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)

vm_ip_data = {}
# Save the data to a JSON file
with open('vm_ips.json') as f:
    vm_ip_data = json.load(f)



def connect_ssh(public_ip, username, private_key_path):
    """
    Establishes an SSH connection and returns the SSH client.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(public_ip, username=username, key_filename=private_key_path)
    return ssh

def is_rollbaccine_installed(ssh):
    """
    Checks if rollbaccine is installed on the remote machine.
    """
    stdin, stdout, stderr = ssh.exec_command('test -d ~/rollbaccine && echo "Installed" || echo "Not installed"')
    installation_status = stdout.read().decode().strip()
    return installation_status == "Installed"

def install_rollbaccine(ssh, username, script_path):
    """
    Installs rollbaccine by copying the installation script and executing it.
    """
    sftp = ssh.open_sftp()
    remote_script_path = f'/home/{username}/install_rollbaccine.sh'
    sftp.put(script_path, remote_script_path)
    sftp.close()
    
    print(f"Making script executable on remote host")
    ssh.exec_command(f'chmod +x {remote_script_path}')
    print(f"Running install script on remote host")
    stdin, stdout, stderr = ssh.exec_command(f'sudo {remote_script_path}')
    for line in stdout.read().splitlines():
        print(line.decode())

def is_fio_installed(ssh):
    """
    Checks if fio is installed on the remote machine.
    """
    stdin, stdout, stderr = ssh.exec_command('which fio')
    fio_path = stdout.read().decode().strip()
    return fio_path != ''

def install_fio(ssh):
    """
    Installs fio on the remote machine.
    """
    install_fio_commands = [
        "sudo apt-get update",
        "sudo apt-get install -y fio"
    ]
    for cmd in install_fio_commands:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            print(f"Error running command '{cmd}': {stderr.read().decode().strip()}")
            return False
    return True

def is_python3_installed(ssh):
    """
    Checks if Python 3 is installed on the remote machine.
    """
    stdin, stdout, stderr = ssh.exec_command('which python3')
    python_path = stdout.read().decode().strip()
    return python_path != ''

def install_python3(ssh):
    """
    Installs Python 3 on the remote machine.
    """
    install_python_commands = [
        "sudo apt-get update",
        "sudo apt-get install -y python3 python3-pip"
    ]
    for cmd in install_python_commands:
        print(f"Executing: {cmd}")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_msg = stderr.read().decode().strip()
            print(f"Error running command '{cmd}': {error_msg}")
            return False
    return True

def get_leader_commands(username):
    """
    Returns the list of commands to execute on the leader VM.
    """
    commands = [
        "sudo umount /dev/sdb1",
        f"cd /home/{username}/rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        'echo "0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 1 2 0 true 250000 abcdefghijklmnop 12340" | sudo dmsetup create rollbaccine1'
    ]
    return commands

def get_follower_commands(username, private_ip_0):
    """
    Returns the list of commands to execute on the follower VM.
    """
    commands = [
        "sudo umount /dev/sdb1",
        f"cd /home/{username}/rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        f'echo "0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 1 2 1 false 250000 abcdefghijklmnop 12350 {private_ip_0} 12340" | sudo dmsetup create rollbaccine2'
    ]
    return commands

def run_commands_on_vm(compute_client, resource_group_name, vm_name, commands):
    """
    Runs a list of commands on the VM via Azure Compute Client.
    """
    command_parameters = {
        'command_id': 'RunShellScript',
        'script': commands
    }
    poller = compute_client.virtual_machines.begin_run_command(
        resource_group_name,
        vm_name,
        command_parameters
    )
    result = poller.result()  # Wait for the command to complete
    
    for output in result.value:
        print(output.message)

def ssh_and_execute(public_ip, username, private_key_path, script_path, is_leader, vm_name, compute_client, resource_group_name, private_ip_0):
    try:
        ssh = connect_ssh(public_ip, username, private_key_path)
    except Exception as e:
        print(f"Failed to connect to {public_ip}: {e}")
        return False

    try:
        print(f"Checking if rollbaccine is already installed on {public_ip}")
        if is_rollbaccine_installed(ssh):
            print(f"Rollbaccine is already installed on {public_ip}")
        else:
            print(f"Installing rollbaccine on {public_ip}")
            install_rollbaccine(ssh, username, script_path)
        
        print(f"Checking if fio is installed on {public_ip}")
        if not is_fio_installed(ssh):
            print(f"fio not found on {public_ip}. Installing fio...")
            if not install_fio(ssh):
                ssh.close()
                return False
            print(f"fio installed on {public_ip}")
        else:
            print(f"fio is already installed on {public_ip}")
        
        print(f"Checking if Python 3 is installed on {public_ip}")
        if not is_python3_installed(ssh):
            print(f"Python 3 not found on {public_ip}. Installing Python 3...")
            if not install_python3(ssh):
                ssh.close()
                return False
            print(f"Python 3 installed successfully on {public_ip}")
        else:
            print(f"Python 3 is already installed on {public_ip}")
        
    finally:
        ssh.close()
    
    if is_leader:
        print(f"Running leader-specific commands on {vm_name}")
        commands = get_leader_commands(username)
    else:
        print(f"Running follower-specific commands on {vm_name}")
        commands = get_follower_commands(username, private_ip_0)

    run_commands_on_vm(compute_client, resource_group_name, vm_name, commands)

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

def run_multiple_fio_benchmarks(public_ip, username, private_key_path, vm_name, parameters_list):
    """
    Execute multiple FIO benchmarks on the VM and retrieve the results.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(public_ip, username=username, key_filename=private_key_path)
        sftp = ssh.open_sftp()
        for idx, parameters in enumerate(parameters_list):
            job_name = parameters.get('name', f'benchmark_{vm_name}_{idx}')
            write_mode = parameters.get('write_mode', 'readwrite')
            direct = parameters.get('direct', 0)
            bs = parameters.get('bs', '4k')
            filename = parameters.get('filename', '/dev/mapper/rollbaccine1')
            runtime = parameters.get('runtime', 120)
            status_interval = parameters.get('status_interval', 5)
            ramp_time = parameters.get('ramp_time', 0)
            output_file = f'/home/{username}/{job_name}_fio_results.json'

            # Include size? 

            # Build the FIO command
            fio_command = (
                f'sudo fio '
                f'--name={job_name} '
                f'--rw={write_mode} '
                f'--direct={direct} '
                f'--bs={bs} '
                f'--runtime={runtime} '
                f'--filename={filename} '
                f'--output-format=json '
                f'--status-interval={status_interval} '
                f'--ramp_time={ramp_time} '
            )

            fio_command += f' > {output_file}'

            print(f"Running FIO benchmark '{job_name}' on {vm_name}")
            print(f"FIO command: {fio_command}")

            # Execute the FIO command on the remote VM
            stdin, stdout, stderr = ssh.exec_command(fio_command)
            # Monitor the output
            while not stdout.channel.exit_status_ready():
                if stdout.channel.recv_ready():
                    output = stdout.channel.recv(1024).decode()
                    print(output, end='')
                sleep(status_interval)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                print(f"\nFIO benchmark '{job_name}' completed successfully on {public_ip}")
            else:
                error_msg = stderr.read().decode().strip()
                print(f"FIO benchmark '{job_name}' failed on {public_ip}: {error_msg}")
                continue  # Proceed to the next benchmark

            local_result_dir = './results'
            os.makedirs(local_result_dir, exist_ok=True)
            local_result_path = os.path.join(local_result_dir, f'{vm_name}_{job_name}_fio_results.json')
            print(f"Retrieving FIO results for '{job_name}' from {public_ip} to {local_result_path}")
            try:
                sftp.get(output_file, local_result_path)
                print(f"FIO results for '{job_name}' saved to {local_result_path}")
                with open(local_result_path, 'r') as f:
                    fio_result = json.load(f)
                csv_output_file = os.path.join(local_result_dir, 'fio_results.csv')
                if not os.path.exists(csv_output_file):
                    with open(csv_output_file, mode='w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow([
                            "Job Name", "FIO Job", "Read IOPS", "Read Bandwidth (KB/s)",
                            "Read Latency (ns)", "Write IOPS", "Write Bandwidth (KB/s)",
                            "Write Latency (ns)"
                        ])
                save_to_csv(job_name, fio_result, csv_output_file)
                print(f"Results for '{job_name}' saved to {csv_output_file}")
            except Exception as e:
                print(f"Error retrieving FIO results for '{job_name}' from {public_ip}: {e}")
                continue  # Proceed to the next benchmark
    except Exception as e:
        print(f"Error running FIO benchmarks on {public_ip}: {e}")
        return False
    finally:
        if 'sftp' in locals():
            sftp.close()
        ssh.close()
    return True  # Indicate success


# Get the private IP of the leader VM
private_ip_0 = vm_ip_data['rollbaccineNum0']['private_ip']

# Run commands on all VMs
for vm_name in vm_ip_data.keys():
    is_leader = True if vm_name == 'rollbaccineNum0' else False
    ssh_and_execute(vm_ip_data[vm_name]['public_ip'], USERNAME, PRIVATE_KEY_PATH, SCRIPT_PATH, is_leader, vm_name, compute_client, RESOURCE_GROUP_NAME, private_ip_0)

fio_parameters_list = [
    ####################
    #    READ/WRITE   #
    #####################

    {
        'name': 'benchmark_seq_read',
        'write_mode': 'read',
        'bs': '4k',                  
        'size': '10G',               
        'direct': 0,
        'ramp_time': 45,                 
    },
    {
        'name': 'benchmark_seq_write',
        'write_mode': 'write',
        'bs': '4k',                  
        'size': '10G',               
        'direct': 0,                 
    },
    {
        'name': 'benchmark_rand_read',
        'write_mode': 'randread',
        'bs': '4k',                  
        'size': '10G',               
        'direct': 0,                 
    },
    {
        'name': 'benchmark_rand_write',
        'write_mode': 'randwrite',
        'bs': '4k',                  
        'size': '10G',               
        'direct': 0,                 
    },
    {
        'name': 'benchmark_randrw',
        'write_mode': 'randrw',
        'bs': '4k',                  
        'size': '10G',               
        'direct': 0,                 
    },
    ]


# Run Fio on Leader
success = run_multiple_fio_benchmarks(
    vm_ip_data['rollbaccineNum0']['public_ip'],
    USERNAME,
    PRIVATE_KEY_PATH,
    'rollbaccineNum0',
    fio_parameters_list
)
print(success)