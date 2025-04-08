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
PRIMARY_OUTFILE = "results/recovery/crash_primary_out.txt"
BACKUP_OUTFILE = "results/recovery/crash_backup_out.txt"

# Exist on either timeout or recovery complete
def log_primary_or_backup(ssh: SSHClient, is_primary: bool, timeout=0, exit_on_recovery_complete=False):
    if is_primary:
        filename = PRIMARY_OUTFILE
        dm_name = "rollbaccine1"
    else:
        filename = BACKUP_OUTFILE
        dm_name = "rollbaccine2"

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
def run(recover_primary: bool):
    # Create resources
    BENCHMARK_NAME = "postgres"
    SYSTEM = System.ROLLBACCINE
    print(f"Creating a VM under '{BENCHMARK_NAME}' benchmark and '{SYSTEM}' system.")
    subprocess_execute([f"./launch.sh -b {BENCHMARK_NAME} -s {SYSTEM} -n 3"])
    ssh_executor = SSH(SYSTEM, BENCHMARK_NAME)

    print("Connecting to VMs and setting up main VMs")
    print(f"\033[92mPlease run `tail -f {ssh_executor.output_file}` to see the execution log on the servers.\033[0m")
    ssh_executor.clear_output_file()
    # Only clear the file of the thing we're running
    main_outfile = PRIMARY_OUTFILE if recover_primary else BACKUP_OUTFILE
    open(main_outfile, 'w').close()
    
    with open(f'{BENCHMARK_NAME}-{SYSTEM}-vm1.json') as f:
        vm_json = json.load(f)
        connections, public_ips, private_ips, ids = ssh_vm_json_plus(vm_json)
        primary_ssh, primary_public_ip, primary_ip, primary_id = connections[0], public_ips[0], private_ips[0], ids[0]
        backup_ssh, backup_public_ip, backup_ip, backup_id = connections[1], public_ips[1], private_ips[1], ids[1]
    with open(f'{BENCHMARK_NAME}-{SYSTEM}-vm2.json') as f:
        vm_json = json.load(f)
        connections, public_ips, private_ips, ids = ssh_vm_json_plus(vm_json)
        benchmark_ssh, benchmark_public_ip, benchmark_ip, benchmark_id = connections[0], public_ips[0], private_ips[0], ids[0]
    
    print("Installing rollbaccine")
    install_rollbaccine(ssh_executor, primary_ssh)
    install_rollbaccine(ssh_executor, backup_ssh)

    print("Setting up rollbaccine primary")
    success = ssh_executor.exec(primary_ssh, [
        "sudo umount /dev/sdb1",
        "cd rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        f'echo "0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 1 1 true abcdefghijklmnop 12340 2 {backup_ip} 12350" | sudo dmsetup create rollbaccine1'
    ])
    if not success:
        return False
    
    print("Setting up rollbaccine backup")
    success = ssh_executor.exec(backup_ssh, [
        "sudo umount /dev/sdb1",
        "cd rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        f'echo "0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 2 1 false abcdefghijklmnop 12350 1 {primary_ip} 12340" | sudo dmsetup create rollbaccine2'
    ])
    if not success:
        return False
    
    print("Waiting 10 seconds for rollbaccine to finish setup")
    sleep(10)

    print("Mounting ext4 on the primary")
    mount_point = ssh_executor.mount_point(primary_ssh)
    install_ext4(ssh_executor, primary_ssh, mount_point)

    print("Installing Postgres on primary, may take a few minutes")
    success = ssh_executor.exec(primary_ssh, [
        "sudo apt-get -qq update",
        "sudo apt-get install -qq -y postgresql-common",
        # Install to our custom directory
        rf"echo 'data_directory = '\'{DATA_DIR}\' | sudo tee -a /etc/postgresql-common/createcluster.conf",
        f"sudo chown -R postgres:postgres {DATA_DIR}",
        "sudo apt-get install -qq -y postgresql",
        # Listens to public addresses
        r"echo 'listen_addresses = '\'*\' | sudo tee -a /etc/postgresql/*/main/postgresql.conf",
        # Trust all connections
        "echo 'host all all 0.0.0.0/0 trust' | sudo tee -a /etc/postgresql/*/main/pg_hba.conf",
        "sudo systemctl restart postgresql.service",
        "sudo -u postgres /usr/lib/postgresql/*/bin/createuser -s -i -d -r -l -w admin",
        "sudo -u postgres /usr/lib/postgresql/*/bin/createdb benchbase",
        # NEW: Don't let postgres automatically start on boot, because we need to recover disk first
        "sudo systemctl disable postgresql.service"
    ])
    if not success:
        return False

    print("Installing Benchbase on benchmarking VM, may also take a few minutes")
    success = ssh_executor.exec(benchmark_ssh, [
        "wget -nv https://github.com/cmu-db/benchbase/archive/refs/tags/v2023.tar.gz",
        "tar -xzf v2023.tar.gz",
        # Install Java
        "sudo apt-get -qq update",
        "sudo apt-get -y -qq install openjdk-21-jre",
        "cd benchbase-2023",
        "./mvnw -q clean package -P postgres -DskipTests",
        "cd target",
        "tar xzf benchbase-postgres.tgz"
    ])
    if not success:
        return False
    
    print("Copying config file to benchmarking VM")
    REMOTE_CONFIG = "benchbase-2023/target/benchbase-postgres/config/tpcc_config.xml"
    upload(benchmark_ssh, "src/tools/benchmarking/postgres/tpcc_config.xml", REMOTE_CONFIG)

    print("Modifying config file")
    success = ssh_executor.exec(benchmark_ssh, [f"sed -i 's/localhost/{primary_ip}/g' {REMOTE_CONFIG}"])
    if not success:
        return False

    print(f"Running TPCC in the background, killing it after {BENCHMARK_TIMEOUT * 2} seconds")
    OUTPUT_DIR = f"/home/{getuser()}/results"
    ssh_execute_background(benchmark_ssh, [
        f"mkdir -p {OUTPUT_DIR}",
        "cd ~/benchbase-2023/target/benchbase-postgres",
        f"timeout {BENCHMARK_TIMEOUT * 2} java -jar benchbase.jar -b tpcc -c config/tpcc_config.xml -d {OUTPUT_DIR} --clear=true --create=true --load=true --execute=true"
    ])

    print(f"Waiting {BENCHMARK_TIMEOUT} seconds for the benchmark to run")
    main_ssh = primary_ssh if recover_primary else backup_ssh
    main_public_ip = primary_public_ip if recover_primary else backup_public_ip
    main_id = primary_id if recover_primary else backup_id
    log_primary_or_backup(main_ssh, recover_primary, BENCHMARK_TIMEOUT)

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

    print("Messing up the disk with 10 MB of zeros")
    success = ssh_executor.exec(main_ssh, [
        "sudo umount /dev/sdb1",
        "sudo dd if=/dev/zero of=/dev/sdb1 bs=1M count=10"
    ])
    if not success:
        return False

    print("Recovering")
    if recover_primary:
        dm_command = f'echo "0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 3 3 true abcdefghijklmnop 12360 2 {backup_ip} 12350 1 {primary_ip} 12340 2 {backup_ip} 12350" | sudo dmsetup create rollbaccine1'
    else:
        dm_command = f'echo "0 $(sudo blockdev --getsz /dev/sdb1) rollbaccine /dev/sdb1 3 3 false abcdefghijklmnop 12360 1 {primary_ip} 12340 1 {primary_ip} 12340 2 {backup_ip} 12350" | sudo dmsetup create rollbaccine2'
    success = ssh_executor.exec(main_ssh, [
        "cd rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        dm_command
    ])
    if not success:
        return False
        

    print(f"Wait for recovery to complete")
    log_primary_or_backup(main_ssh, recover_primary, 0, True)

    if recover_primary:
        print("Remounting the file system and restarting postgres")
        success = ssh_executor.exec(main_ssh, [
            f"sudo mount {mount_point} {MOUNT_DIR}",
            "sudo systemctl start postgresql.service"
        ])
        if not success:
            return False

    print(f"Running TPCC again for {BENCHMARK_TIMEOUT * 2} seconds")
    ssh_execute_background(benchmark_ssh, [
        "cd ~/benchbase-2023/target/benchbase-postgres",
        f"timeout {BENCHMARK_TIMEOUT * 2} java -jar benchbase.jar -b tpcc -c config/tpcc_config.xml -d {OUTPUT_DIR} --clear=true --create=true --load=true --execute=true"
    ])
    
    print(f"Waiting {BENCHMARK_TIMEOUT} seconds for the benchmark to run")
    log_primary_or_backup(main_ssh, recover_primary, BENCHMARK_TIMEOUT)

    print("Benchmark completed, deleting resources")
    primary_ssh.close()
    backup_ssh.close()
    benchmark_ssh.close()
    subprocess_execute([f"./cleanup.sh -b {BENCHMARK_NAME} -s {SYSTEM}"])

if __name__ == "__main__":
    # True = recover primary, False = recover backup
    run(sys.argv[1] == "True")