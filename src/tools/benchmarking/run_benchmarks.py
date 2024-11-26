import subprocess
import csv
import os
import json
import paramiko
import itertools
import time
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
# Custom imports
from benchmark import *
from utils import *
from setup_azure_vm import setup_azure_vms
from delete_azure_vm import delete_resources
from fio.fio_utils import FioBenchmark

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
RESOURCE_GROUP_NAME = config['resource_group_name']

compute_client = ComputeManagementClient(credential=DefaultAzureCredential(), subscription_id=SUBSCRIPTION_ID)

def connect_ssh(public_ip, username, private_key_path):
    """
    Establishes an SSH connection and returns the SSH client.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(public_ip, username=username, key_filename=private_key_path)
    return ssh

def install_rollbaccine(ssh, username):
    """
    Installs rollbaccine by copying the installation script and executing it.
    """
    if not is_installed(ssh, 'test -d ~/rollbaccine && echo "Installed"'):
        remote_script_path = f'/home/{username}/install_rollbaccine.sh'
        upload(ssh, os.path.join(os.getenv('BASE_PATH'), config['install_script_path']), remote_script_path)
        ssh_execute(ssh, [
            f'chmod +x {remote_script_path}',
            f'sudo {remote_script_path}'
        ])

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

def get_backup_commands(username, private_ip_0):
    """
    Returns the list of commands to execute on the backup.
    """
    commands = [
        "sudo umount /dev/sdb1",
        f"cd /home/{username}/rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        f'echo "0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 1 2 1 false 250000 abcdefghijklmnop 12350 {private_ip_0} 12340" | sudo dmsetup create rollbaccine2'
    ]
    return commands

def ssh_and_setup(public_ip, username, private_key_path, system_type: System, index, primary_private_ip):
    try:
        ssh = connect_ssh(public_ip, username, private_key_path)
        if system_type == System.UNREPLICATED:
            ssh_execute(ssh, ["sudo umount /dev/sdb1"])
        elif system_type == System.DM:
            # TODO: Set up dm-crypt and dm-integrity
            ssh_execute(ssh, ["sudo umount /dev/sdb1"])
        elif system_type == System.ROLLBACCINE:
            install_rollbaccine(ssh, username)
            # Setup primary and backup
            if index == 0:
                ssh_execute(ssh, get_leader_commands(username))
            elif index == 1:
                ssh_execute(ssh, get_backup_commands(username, primary_private_ip))
    except Exception as e:
        print(f"Connection failed {public_ip}: {e}")
        return
    return ssh

def run_everything(system_type: System, benchmark: Benchmark):
    """
    Function to set up Azure VMs, run FIO benchmarks, and then delete the VMs.
    """
    num_vms = benchmark.num_vms()
    # 1 additional VM for the rollbaccine backup
    if system_type == System.ROLLBACCINE:
        num_vms += 1
    
    # Run setup_azure_vm.py to create resources
    setup_azure_vms(num_vms)
    print("Sleeping 10 seconds to give VMs extra time to start")
    time.sleep(10)

    # Load vm_ip_data from 'vm_ips.json' generated by setup_azure_vm.py
    with open('vm_ips.json') as f:
        vm_ip_data = json.load(f)

    # Setup all VMs and add SSH connections to the list
    # For rollbaccine, the primary is always the 1st VM, the backup is always the 2nd
    # The backup is not exposed to the benchmark, so we don't add it to connections
    print("Connecting to VMs and setting up")
    connections = []
    i = 0
    primary_private_ip = ''
    for vm_name in vm_ip_data.keys():
        ssh = ssh_and_setup(vm_ip_data[vm_name]['public_ip'], USERNAME, PRIVATE_KEY_PATH, system_type, i, primary_private_ip)
        if system_type == System.ROLLBACCINE:
            if i == 0:
                primary_private_ip = vm_ip_data[vm_name]['private_ip']
            elif i == 1:
                ssh.close()
                i += 1
                continue
        connections.append(ssh)
        i += 1
            
    # Install everything the benchmark needs on the VM
    print(f"Installing {benchmark.name()} on the main VM")
    benchmark_install_success = benchmark.install(connections)
    if not benchmark_install_success:
        print(f"Failed to install {benchmark.name()} on the VM")
        return False
    
    # Close all SSH connections except for the one running the benchmark
    for (index, ssh) in enumerate(connections):
        if index != benchmark.benchmarking_vm():
            ssh.close()
    
    # Copy the repo to the VM that runs the benchmark, install python, and run the benchmark
    print("Copying repo to benchmarking VM")
    try:
        ssh = connections[benchmark.benchmarking_vm()]
        # Copy the repo to the VM because it contains our python script
        install_rollbaccine(ssh, USERNAME)

        # Install python and the requirements
        python_installed_success = ssh_execute(ssh, [
            "sudo apt-get update",
            "sudo apt-get install -y python3 python3-pip",
            f"pip3 install --break-system-packages -r /home/{USERNAME}/rollbaccine/src/tools/benchmarking/requirements.txt"
        ])
        if not python_installed_success:
            ssh.close()
            return False
        
        print("Running benchmark")
        stdin, stdout, stderr = ssh.exec_command(f"python3 /home/{USERNAME}/rollbaccine/src/tools/benchmarking/{benchmark.filename()} {system_type}", get_pty=True)
        for line in iter(stdout.readline, ""):
            print(line, end="")
        ssh.close()
        print("Benchmark completed, deleting resources")
    except Exception as e:
        print(f"Failed to run benchmark: {e}")
        return False

    # Run delete_azure_vm.py to delete resources
    delete_resources()

# Run benchmarks on Normal Disk
run_everything(System.UNREPLICATED, FioBenchmark())

