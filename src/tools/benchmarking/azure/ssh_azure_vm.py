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

STARTING_VM = 'PowerState/running'
STOPPING_VM = 'PowerState/stopped'

def manage_vm_power_state(vm_name, action):
    action_name = "start" if action == STARTING_VM else "stop"
    print(f"{action_name} VM: {vm_name}")
    start_operation = compute_client.virtual_machines.begin_start(RESOURCE_GROUP_NAME, vm_name)
    start_operation.wait()

    # Poll the VM status until it is running
    while True:
        vm = compute_client.virtual_machines.get(RESOURCE_GROUP_NAME, vm_name, expand='instanceView')
        statuses = vm.instance_view.statuses
        for status in statuses:
            if status.code == action:
                print(f"VM {vm_name} is now {action.split('/')[1]}.")
                return
        print(f"Waiting for VM {vm_name} to {action_name}...")
        sleep(10)



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
    
    except Exception as e:
        print(f"Failed to connect to {public_ip}: {e}")

    ssh.close()

    commands = [
    "sudo umount /dev/sdb1 || true",
    f"cd /home/{username}/rollbaccine/src",
    "sudo insmod rollbaccine.ko"
    ]

    # Install rollbaccine
    if is_leader:
        print(f"Running leader-specific commands on {vm_name}")
        commands.append(
            "echo \"0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 1 2 0 true 250000 abcdefghijklmnop 12340\" | sudo dmsetup create rollbaccine1"
        )
    else:
        print(f"Running follower-specific commands on {vm_name}")
        commands.append(
            f"echo \"0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 1 2 1 false 250000 abcdefghijklmnop 12350 {private_ip_0} 12340\" | sudo dmsetup create rollbaccine2"
        )

    command_parameters = {
        'command_id': 'RunShellScript',
        'script': commands
    }

    poller = compute_client.virtual_machines.begin_run_command(
        RESOURCE_GROUP_NAME,
        vm_name,
        command_parameters
    )
    result = poller.result()  # Wait for the command to complete

    for output in result.value:
        print(output.message)

# Start all VMs
for vm_name in vm_ip_data.keys():
    manage_vm_power_state(vm_name, STARTING_VM)

# Get the private IP of the leader VM
private_ip_0 = vm_ip_data['rollbaccineNum0']['private_ip']

# Run commands on all VMs
for vm_name in vm_ip_data.keys():
    is_leader = True if vm_name == 'rollbaccineNum0' else False
    ssh_and_execute(vm_ip_data[vm_name]['public_ip'], USERNAME, PRIVATE_KEY_PATH, SCRIPT_PATH, is_leader)

# # Stop all VMs
# for vm_name in vm_ip_data.keys():
#     manage_vm_power_state(vm_name, STOPPING_VM)