import subprocess
import csv
import os
import json
import paramiko
import itertools
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from fio_utils import is_fio_installed, install_fio, run_multiple_fio_benchmarks
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
        
        if is_leader:
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

def ssh_and_execute_normal_disk(public_ip, username, private_key_path, vm_name):
    """
    Connects to the VM via SSH and ensures that fio and Python 3 are installed.
    """
    try:
        ssh = connect_ssh(public_ip, username, private_key_path)
    except Exception as e:
        print(f"Failed to connect to {public_ip}: {e}")
        return False

    try:
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

def run_everything(fio_parameters_list, numjobs_list, is_rollbaccine=True):
    """
    Function to set up Azure VMs, run FIO benchmarks, and then delete the VMs.
    """
    import subprocess
    import json
    import time

    # Run setup_azure_vm.py to create resources
    print("Running setup_azure_vm.py to create Azure VMs")
    try:
        subprocess.run(['python3', 'setup_azure_vm.py'], check=True)
        print("Azure VMs setup completed successfully")
    except subprocess.CalledProcessError as e:
        print(f"Error setting up Azure VMs: {e}")
        return  # Exit the function if setup fails

    # Load vm_ip_data from 'vm_ips.json' generated by setup_azure_vm.py
    with open('vm_ips.json') as f:
        vm_ip_data = json.load(f)

    # Run ssh_and_execute on all VMs
    for vm_name in vm_ip_data.keys():
        if is_rollbaccine:
            private_ip_0 = vm_ip_data['rollbaccineNum0']['private_ip']
            is_leader = True if vm_name == 'rollbaccineNum0' else False
            ssh_and_execute(vm_ip_data[vm_name]['public_ip'], USERNAME, PRIVATE_KEY_PATH, SCRIPT_PATH, is_leader, vm_name, compute_client, RESOURCE_GROUP_NAME, private_ip_0)
        else:
            ssh_and_execute_normal_disk(vm_ip_data[vm_name]['public_ip'], USERNAME, PRIVATE_KEY_PATH, vm_name)

    # Run FIO benchmarks
    for fio_parameters_template in fio_parameters_list:
        success = run_multiple_fio_benchmarks(
            vm_ip_data['rollbaccineNum0']['public_ip'],
            USERNAME,
            PRIVATE_KEY_PATH,
            'rollbaccineNum0',
            fio_parameters_template,
            numjobs_list,
            is_rollbaccine
        )
        print(f"FIO benchmarks for '{fio_parameters_template['name']}' completed:", success)

    # Run delete_azure_vm.py to delete resources
    print("Running delete_azure_vm.py to delete Azure VMs")
    try:
        subprocess.run(['python3', 'delete_azure_vm.py'], check=True)
        print("Azure VMs deleted successfully")
    except subprocess.CalledProcessError as e:
        print(f"Error deleting Azure VMs: {e}")
        return  # Exit the function if deletion fails

# Possible values for each parameter
io_directions = ['read', 'write']
sequentialities = ['seq', 'rand']
bufferings = [1, 0]  # direct=1 (Direct I/O) or direct=0 (Buffered I/O)
persistences = [1, 0]  # fsync=1 (Synchronous) or fsync=0 (Asynchronous)

# Generate all permutations
all_combinations = list(itertools.product(io_directions, sequentialities, bufferings, persistences))

fio_parameters_list = []

for io_direction, sequentiality, direct_io, fsync in all_combinations:
    # Construct the 'rw' parameter for FIO
    if sequentiality == 'seq':
        rw = io_direction
    else:
        rw = 'rand' + io_direction

    # Build the fio parameter dictionary
    fio_param = {
        'name': f'{sequentiality}_{io_direction}_direct{direct_io}_fsync{fsync}',
        'write_mode': rw,
        'bs': '4k',
        'size': '10G',
        'direct': direct_io,
        'ramp_time': 45,
        'iodepth': 1,  # Default iodepth
        'group_reporting': True,
    }

    # Add fsync parameter if persistence is required
    if fsync == 1:
        fio_param['fsync'] = 1  # Issue fsync after each write

    fio_parameters_list.append(fio_param)

# Define the list of numjobs (thread counts) you want to test
numjobs_list = [1, 2, 4, 8, 16]

# Run benchmarks on Rollbaccine
# run_everything(fio_parameters_list, numjobs_list, is_rollbaccine=True)

# Run benchmarks on Normal Disk
run_everything(fio_parameters_list, numjobs_list, is_rollbaccine=False)