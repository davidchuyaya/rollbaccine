import paramiko
import json
import os
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

def start_vm(vm_name):
    print(f"Starting VM: {vm_name}")
    start_operation = compute_client.virtual_machines.begin_start(RESOURCE_GROUP_NAME, vm_name)
    start_operation.wait()

    # Poll the VM status until it is running
    while True:
        vm = compute_client.virtual_machines.get(RESOURCE_GROUP_NAME, vm_name, expand='instanceView')
        statuses = vm.instance_view.statuses
        for status in statuses:
            if status.code == 'PowerState/running':
                print(f"VM {vm_name} is now running.")
                return
        print(f"Waiting for VM {vm_name} to start...")
        sleep(10)  # Wait 10 seconds before checking again

def ssh_and_execute(public_ip, username, private_key_path, script_path, is_leader):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(public_ip, username=username, key_filename=private_key_path)

        print(f"Checking if rollbaccine is already installed on {public_ip}")
        stdin, stdout, stderr = ssh.exec_command('test -d ~/rollbaccine && echo "Installed" || echo "Not installed"')
        installation_status = stdout.read().decode().strip()

        # Install rollbaccine
        if installation_status == "Installed":
            print(f"Rollbaccine is already installed on {public_ip}")
        else:
            print(f"Installing rollbaccine on {public_ip}")
            # Copy script onto machine
            sftp = ssh.open_sftp()
            remote_script_path = f'/home/{username}/install_rollbaccine.sh'
            sftp.put(script_path, remote_script_path)
            sftp.close()
            
            # Execute the script
            print(f"Making script executable on {public_ip}")
            ssh.exec_command(f'chmod +x {remote_script_path}')
            print(f"Running install script on {public_ip}")
            stdin, stdout, stderr = ssh.exec_command(f'sudo {remote_script_path}')
            for line in stdout.read().splitlines():
                print(line)

        # Run leader/follower-specific commands
        if is_leader:
            print(f"Running leader-specific commands on {public_ip}")
            commands = [
                "sudo umount /dev/sdb1",
                "cd rollbaccine/src",
                "sudo insmod rollbaccine.ko",
                f"echo \"0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 1 2 0 true 250000 abcdefghijklmnop 12340\" | sudo dmsetup create rollbaccine1"
            ]
        else:
            print(f"Running follower-specific commands on {public_ip}")
            commands = [
                "sudo umount /dev/sdb1",
                "cd rollbaccine/src",
                "sudo insmod rollbaccine.ko",
                f"echo \"0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 1 2 1 false 250000 abcdefghijklmnop 12350 {vm_ip_data['rollbaccineNum0']['private_ip']} 12340\" | sudo dmsetup create rollbaccine2"
            ]

        for cmd in commands:
            print(f"Running command: {cmd}")
            stdin, stdout, stderr = ssh.exec_command(cmd)
            for line in stdout.read().splitlines():
                print(line)

        ssh.close()

    except Exception as e:
        print(f"Failed to connect to {public_ip}: {e}")

for vm_name, ip_data in vm_ip_data.items():
    public_ip = ip_data['public_ip']
    is_leader = True if vm_name == 'rollbaccineNum0' else False
    start_vm(vm_name)
    ssh_and_execute(public_ip, USERNAME, PRIVATE_KEY_PATH, SCRIPT_PATH, is_leader)