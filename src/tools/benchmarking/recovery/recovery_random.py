import os
import sys
import time
from getpass import getuser

# Add the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from run_benchmarks import *
from benchmark import *
from utils import *

# How long to let the primary run before restarting it
BENCHMARK_TIMEOUT = 100
# How often to check if the primary/backup are done recovering
CHECK_FREQUENCY = 5

def outfile(is_primary: bool, gb_to_corrupt: int) -> str:
    if is_primary:
        return f"results/crash_primary_out_random{str(gb_to_corrupt)}.txt"
    return f"results/crash_backup_out_random{str(gb_to_corrupt)}.txt"

# Exist on either timeout or recovery complete
def log_primary_or_backup(ssh: SSHClient, is_primary: bool, gb_to_corrupt: int, timeout=0, exit_on_recovery_complete=False):
    filename = outfile(is_primary, gb_to_corrupt)
    dm_name = "rollbaccine1" if is_primary else "rollbaccine2"

    print(f"\033[92mPlease run `tail -f {filename}` to see how the {"primary" if is_primary else "backup"} is progressing.\033[0m")
    start = time.time()
    with open(filename, "a") as stdout_file:
        while True:
            stdin, stdout, stderr = ssh.exec_command(f"sudo dmsetup status {dm_name}", get_pty=True)
            end = time.time()
            stdout_file.write(f"Time: {end}\n")
            for line in stdout:
                # Log the data we care about
                if "Latest write index" in line or "Num pages requested" in line or "Hashes received" in line or "ballot" in line:
                    stdout_file.write(line)
                if "ballot 3, seen_ballot: 3" in line and exit_on_recovery_complete:
                    return
            stdout_file.flush()
            if timeout > 0 and end - start > timeout:
                return
            
            # Sleep and check again
            sleep(CHECK_FREQUENCY)

def restart(id: str):
    print(f"Restarting VM with ID {id}, may take up to 15 minutes")
    subprocess_execute([f"az vm restart --ids {id}"])

# Additionally fetch the ID field so we can restart the VM
def ssh_vm_json_plus(vm_json) -> Tuple[List[SSHClient], List[str], List[str], List[str]]:
    connections = []
    public_ips = []
    private_ips = []
    ids = []
    # Different json formats based on whether we launched 1 or more VMs
    if isinstance(vm_json, dict):
        public_ip = vm_json['publicIpAddress']
        public_ips.append(public_ip)
        connections.append(connect_ssh(public_ip))
        private_ips.append(vm_json['privateIpAddress'])
        ids.append(vm_json['id'])
    else:
        for vm in vm_json:
            public_ip = vm['publicIps']
            public_ips.append(public_ip)
            connections.append(connect_ssh(public_ip))
            private_ips.append(vm['privateIps'])
            ids.append(vm['id'])
    return connections, public_ips, private_ips, ids

# Mostly copied from run_benchmarks:run_everything
def run(recover_primary: bool, gb_to_corrupt: int):
    # Create resources
    BENCHMARK_NAME = "postgres"
    SYSTEM = System.ROLLBACCINE
    print(f"Creating a VM under '{BENCHMARK_NAME}' benchmark and '{SYSTEM}' system.")

    unique_str = f"recoverPrimary{recover_primary}Random{str(gb_to_corrupt)}"
    subprocess_execute([f"./launch.sh -b {BENCHMARK_NAME} -s {SYSTEM} -n 2 -m 0 -e {unique_str}"])
    ssh_executor = SSH(SYSTEM, BENCHMARK_NAME, unique_str)

    print("Connecting to VMs and setting up main VMs")
    print(f"\033[92mPlease run `tail -f {ssh_executor.output_file}` to see the execution log on the servers.\033[0m")
    ssh_executor.clear_output_file()
    # Only clear the file of the thing we're running
    main_outfile = outfile(recover_primary, gb_to_corrupt)
    open(main_outfile, 'w').close()
    
    with open(f'{BENCHMARK_NAME}-{SYSTEM}-{unique_str}-vm1.json') as f:
        vm_json = json.load(f)
        connections, public_ips, private_ips, ids = ssh_vm_json_plus(vm_json)
        primary_ssh, primary_public_ip, primary_ip, primary_id = connections[0], public_ips[0], private_ips[0], ids[0]
        backup_ssh, backup_public_ip, backup_ip, backup_id = connections[1], public_ips[1], private_ips[1], ids[1]
    
    print("Installing rollbaccine")
    install_rollbaccine(ssh_executor, primary_ssh)
    install_rollbaccine(ssh_executor, backup_ssh)

    print("Setting up rollbaccine primary")
    success = ssh_executor.exec(primary_ssh, [
        "sudo umount /dev/sdb1",
        "cd rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        f'echo "0 $(sudo blockdev --getsz /dev/sdb) rollbaccine /dev/sdb 1 1 true abcdefghijklmnop 1 0 default 12340 false false 2" | sudo dmsetup create rollbaccine1',
    ])
    if not success:
        return False
    
    print("Setting up rollbaccine backup")
    success = ssh_executor.exec(backup_ssh, [
        "sudo umount /dev/sdb1",
        "cd rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        f'echo "0 $(sudo blockdev --getsz /dev/sdb) rollbaccine /dev/sdb 2 1 false abcdefghijklmnop 1 0 default 12350 false false 1 {primary_ip} 12340" | sudo dmsetup create rollbaccine2'
    ])
    if not success:
        return False
    
    print("Waiting 10 seconds for rollbaccine to finish setup")
    sleep(10)

    print(f"Writing ones to {gb_to_corrupt}GBs of /dev/mapper/rollbaccine1 on the primary, may take {3 * gb_to_corrupt} seconds")
    start = time.time()
    success = ssh_executor.exec(primary_ssh, [
        f'sudo bash -c "dd if=<(tr \'\\000\' \'\\377\' < /dev/zero) of=/dev/mapper/rollbaccine1 bs=1G count={gb_to_corrupt} iflag=fullblock"'
    ])
    if not success:
        return False
    end = time.time()
    print(f"Took {end - start} seconds to write {gb_to_corrupt}GBs of ones to Rollbaccine")

    main_ssh = primary_ssh if recover_primary else backup_ssh
    main_public_ip = primary_public_ip if recover_primary else backup_public_ip
    main_id = primary_id if recover_primary else backup_id

    print("Restarting the VM")
    main_ssh.close()
    start = time.time()
    restart(main_id)
    
    print(f"Reconnecting to: {main_public_ip}, will retry until we can connect")
    while True:
        try:
            main_ssh = connect_ssh(main_public_ip)
            break
        except:
            print("SSH failed, retrying in 10 seconds")
            sleep(10)
    
    end = time.time()
    print(f"Took {end - start} seconds to restart, reconnecting")

    with open(main_outfile, "a") as stdout_file:
        stdout_file.write(f"Recovery time: {end - start}\n")

    print(f"Messing up the disk with {gb_to_corrupt}GBs of zeros, may take {gb_to_corrupt} seconds")
    start = time.time()
    success = ssh_executor.exec(main_ssh, [
        f"sudo dd if=/dev/zero of=/dev/sdb bs=1G count={gb_to_corrupt}"
    ])
    if not success:
        return False
    end = time.time()
    print(f"Took {end - start} seconds to write {gb_to_corrupt}GBs of zeros to /dev/sdb")

    print("Recovering")
    if recover_primary:
        dm_command = f'echo "0 $(sudo blockdev --getsz /dev/sdb) rollbaccine /dev/sdb 3 3 true abcdefghijklmnop 1 0 default 12360 false true 2 {backup_ip} 12350 1 {primary_ip} 12340 2 {backup_ip} 12350" | sudo dmsetup create rollbaccine1'
    else:
        dm_command = f'echo "0 $(sudo blockdev --getsz /dev/sdb) rollbaccine /dev/sdb 3 3 false abcdefghijklmnop 1 0 default 12360 false true 1 {primary_ip} 12340 1 {primary_ip} 12340 2 {backup_ip} 12350" | sudo dmsetup create rollbaccine2'
    success = ssh_executor.exec(main_ssh, [
        "cd rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        dm_command
    ])
    if not success:
        return False

    print(f"Wait for recovery to complete")
    log_primary_or_backup(main_ssh, recover_primary, gb_to_corrupt, 0, True)

    print("Benchmark completed, deleting resources")
    primary_ssh.close()
    backup_ssh.close()
    subprocess_execute([f"./cleanup.sh -b {BENCHMARK_NAME} -s {SYSTEM} -e {unique_str}"])

if __name__ == "__main__":
    # 1. True = recover primary, False = recover backup
    # 2. How many GBs to corrupt
    run(sys.argv[1] == "True", int(sys.argv[2]))