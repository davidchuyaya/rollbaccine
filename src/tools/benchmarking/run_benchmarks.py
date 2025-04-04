import json
import os
import sys
from time import sleep
from typing import Tuple
import paramiko
from getpass import getuser
# Custom imports
from benchmark import *
from utils import *
from fio.fio_utils import FioBenchmark
from postgres.postgres_utils import PostgresBenchmark
from filebench.filebench_utils import FileBenchmark
from hdfs.hdfs_utils import HDFSBenchmark
from nimble_hdfs.nimble_hdfs_utils import NimbleHDFSBenchmark

def connect_ssh(public_ip):
    """
    Establishes an SSH connection and returns the SSH client.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(public_ip, username=getuser())
    return ssh

def name_to_benchmark(name, nimble_batch_size, nimble_storage):
    """
    Converts a string to a Benchmark object.
    """
    if name == "fio":
        return FioBenchmark()
    elif name == "postgres":
        return PostgresBenchmark()
    elif name == "filebench":
        return FileBenchmark()
    elif name == "hdfs":
        return HDFSBenchmark()
    elif name == "nimble_hdfs":
        return NimbleHDFSBenchmark(nimble_batch_size, nimble_storage)
    else:
        raise ValueError(f"Unknown benchmark name: {name}")

def install_rollbaccine(ssh_executor: SSH, ssh):
    """
    Installs rollbaccine on the VM.
    """
    if not is_installed(ssh, 'test -d ~/rollbaccine && echo 1'):
        ssh_executor.exec(ssh, [
            "sudo apt-get -qq update",
            "sudo apt-get install -qq -y build-essential",
            "git clone -q https://github.com/davidchuyaya/rollbaccine",
            "cd rollbaccine/src",
            "make --silent"
        ])

def download_rollbaccine(ssh_executor: SSH, ssh):
    """
    Download rollbaccine on the VM.
    """
    if not is_installed(ssh, 'test -d ~/rollbaccine && echo 1'):
        ssh_executor.exec(ssh, ["git clone -q https://github.com/davidchuyaya/rollbaccine"])

def get_leader_commands(backup_private_ip):
    """
    Returns the list of commands to execute on the leader VM.
    """
    commands = [
        "sudo umount /dev/sdb1",
        "cd rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        f'echo "0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 1 1 true abcdefghijklmnop 12340 2 {backup_private_ip} 12350" | sudo dmsetup create rollbaccine1'
    ]
    return commands

def get_backup_commands(primary_private_ip):
    """
    Returns the list of commands to execute on the backup.
    """
    commands = [
        "sudo umount /dev/sdb1",
        "cd rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        f'echo "0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 2 1 false abcdefghijklmnop 12350 1 {primary_private_ip} 12340" | sudo dmsetup create rollbaccine2'
    ]
    return commands

def install_ext4(ssh_executor: SSH, ssh: SSHClient, mount_point: str):
    print(f"Installing ext4 at {MOUNT_DIR}")
    ssh_executor.exec(ssh, mount_ext4_commands(mount_point, MOUNT_DIR))
    print(f"Creating {MOUNT_DIR} and giving the user permissions")
    ssh_executor.exec(ssh, [
        f"sudo mkdir -p {DATA_DIR}",
        f"sudo chown -R `whoami` {DATA_DIR}"
    ])

def setup_main_nodes(ssh_executor: SSH, system_type: System, connections: List[SSHClient], private_ips: List[str]):
    for i in range(len(connections)):
        ssh = connections[i]
        mount_point = ssh_executor.mount_point(ssh)

        if not is_installed(ssh, f"test -d {DATA_DIR} && echo 1"):
            print(f"Unmounting {DATA_DIR} then mounting with what we want on VM {i}")

            if system_type == System.UNREPLICATED:
                ssh_executor.exec(ssh, ["sudo umount /dev/sdb1"])
            elif system_type == System.DM:
                print("Setting up dm-crypt and dm-integrity, will take 10 minutes to format the disk")
                ssh_executor.exec(ssh, [
                    "sudo umount /dev/sdb1",
                    # Create an empty file to use as the key
                    "touch emptykey.txt",
                    "sudo cryptsetup luksFormat /dev/sdb1 --integrity aead --cipher aes-gcm-random --key-file emptykey.txt -q",
                    "sudo cryptsetup open --perf-no_read_workqueue --perf-no_write_workqueue --type luks /dev/sdb1 secure --key-file emptykey.txt",
                ])
            elif system_type == System.REPLICATED:
                ssh_executor.exec(ssh, [f"sudo umount {mount_point}"])
            elif system_type == System.ROLLBACCINE:
                install_rollbaccine(ssh_executor, ssh)
                # Setup primary and backup
                if i == 0:
                    ssh_executor.exec(ssh, get_leader_commands(private_ips[1]))
                elif i == 1:
                   ssh_executor.exec(ssh, get_backup_commands(private_ips[0]))

            # If this isn't rollbaccine, then we're immediately to mount the file system.
            # If this is rollbaccine, we'll need to set up the backup first (so they can sync).
            if not system_type == System.ROLLBACCINE:
                install_ext4(ssh_executor, ssh, mount_point)

    if system_type == System.ROLLBACCINE:
        # Wait for the backup to finish setting up
        sleep(10)
        install_ext4(ssh_executor, connections[0], mount_point)
    return mount_point
                

def ssh_vm_json(vm_json) -> Tuple[List[SSHClient], List[str]]:
    connections = []
    private_ips = []
    # Different json formats based on whether we launched 1 or more VMs
    if isinstance(vm_json, dict):
        connections.append(connect_ssh(vm_json['publicIpAddress']))
        private_ips.append(vm_json['privateIpAddress'])
    else:
        for vm in vm_json:
            connections.append(connect_ssh(vm['publicIps']))
            private_ips.append(vm['privateIps'])
    return connections, private_ips

def run_everything(system_type: System, benchmark_name: str, nimble_batch_size: int = 0, nimble_storage: bool = True):
    """
    Function to set up Azure VMs, run FIO benchmarks, and then delete the VMs.
    """
    benchmark = name_to_benchmark(benchmark_name, nimble_batch_size, nimble_storage)
    num_vms = benchmark.num_vms()
    # 1 additional VM for the rollbaccine backup
    if system_type == System.ROLLBACCINE:
        num_vms += 1
    
    # Create resources
    subprocess_execute([f"./launch.sh -b {benchmark_name} -s {system_type} -n {num_vms}"])

    ssh_executor = SSH(system_type, benchmark_name)
    
    storage_name = "rollbaccinenimble" # Must match storage name in ./launch.sh
    storage_key = ""
    if benchmark.needs_storage():
        print("Extracting storage key")
        with open (f'{benchmark_name}-{system_type}-storage.json') as f:
            storage_data = json.load(f)
            storage_key = storage_data[0].get("value")
            print(f"Found storage key: {storage_key}")

    # Setup all VMs and add SSH connections to the list
    print("Connecting to VMs and setting up main VMs")
    print(f"\033[92mPlease run `tail -f {ssh_executor.output_file}` to see the execution log on the servers.\033[0m")
    ssh_executor.clear_output_file()
    connections = []
    private_ips = []
    with open(f'{benchmark_name}-{system_type}-vm1.json') as f:
        vm_json = json.load(f)
        connections, private_ips = ssh_vm_json(vm_json)
        mount_point = setup_main_nodes(ssh_executor, system_type, connections, private_ips)

        if system_type == System.ROLLBACCINE:
            # Disconnect from the backup
            connections[-1].close()
            connections = connections[:-1]
            private_ips = private_ips[:-1]

    if os.path.isfile(f'{benchmark_name}-{system_type}-vm2.json'):
        with open(f'{benchmark_name}-{system_type}-vm2.json') as f:
            vm_json = json.load(f)
            vm2_connections, vm2_private_ips = ssh_vm_json(vm_json)
            connections += vm2_connections
            private_ips += vm2_private_ips
            
    # Install everything the benchmark needs on the VM
    print(f"Installing {benchmark_name} on the main VM")
    benchmark_install_success = benchmark.install(ssh_executor, connections, private_ips, system_type, storage_name, storage_key)
    if not benchmark_install_success:
        print(f"Failed to install {benchmark_name} on the VM")
        return False
    
    # Close all SSH connections except for the one running the benchmark
    for (index, ssh) in enumerate(connections):
        if index != benchmark.benchmarking_vm():
            ssh.close()
    
    # Copy the repo to the VM that runs the benchmark, install python, and run the benchmark
    ssh = connections[benchmark.benchmarking_vm()]
    print("Downloading repo on the benchmarking VM for the python scripts")
    download_rollbaccine(ssh_executor, ssh)

    # Install python and the requirements, create output folder
    print("Install python for benchmarking")
    OUTPUT_DIR = f"/home/{getuser()}/results"
    success = ssh_executor.exec(ssh, [
        "sudo apt-get update",
        "sudo apt-get install -y python3 python3-pip",
        f"cd rollbaccine/src/tools/benchmarking",
        f"pip3 install --break-system-packages -r cloud-requirements.txt",
        f"mkdir -p {OUTPUT_DIR}"
    ])
    if not success:
        return False
    
    print("Running benchmark")
    success = ssh_executor.exec(ssh, [
        f"cd rollbaccine/src/tools/benchmarking",
        f"python3 {benchmark.filename()} {system_type} {mount_point} {OUTPUT_DIR} {nimble_batch_size}"
    ])
    if not success:
        return False

    print("Downloading results")
    download_dir(ssh, OUTPUT_DIR, ".")

    ssh.close()
    print("Benchmark completed, deleting resources")

    subprocess_execute([f"./cleanup.sh -b {benchmark_name} -s {system_type}"])

if __name__ == "__main__":
    run_everything(System[sys.argv[1]], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 0, sys.argv[4] == "true" if len(sys.argv) > 4 else True)

