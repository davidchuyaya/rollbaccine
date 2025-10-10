import os
import sys
from getpass import getuser

# Add the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from run_benchmarks import *
from benchmark import *
from utils import *

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

def connect_gcp_ssh(alias):
    """
    Establishes an SSH connection and returns the SSH client.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    config = paramiko.SSHConfig()
    with open(os.path.expanduser('~/.ssh/config')) as f:
        config.parse(f)
    host_cfg = config.lookup(alias)

    ssh.connect(
        hostname=host_cfg['hostname'],
        username=host_cfg.get('user'),
        key_filename=host_cfg.get('identityfile', [None])[0]
    )
    return ssh

# Mostly copied from run_benchmarks:run_everything
def run():
    # Create resources
    BENCHMARK_NAME = "postgres"
    SYSTEM = System.ROLLBACCINE
    print(f"Creating a VM under '{BENCHMARK_NAME}' benchmark and '{SYSTEM}' system.")

    unique_str = "gcp"
    subprocess_execute([f"./launch.sh -b {BENCHMARK_NAME} -s {SYSTEM} -n 1 -m 1 -e {unique_str}"])
    ssh_executor = SSH(SYSTEM, BENCHMARK_NAME, unique_str)
    

    print("Connecting to Azure VMs")
    print(f"\033[92mPlease run `tail -f {ssh_executor.output_file}` to see the execution log on the servers.\033[0m")
    ssh_executor.clear_output_file()
    
    with open(f'{BENCHMARK_NAME}-{SYSTEM}-{unique_str}-vm1.json') as f:
        vm_json = json.load(f)
        connections, public_ips, private_ips, ids = ssh_vm_json_plus(vm_json)
        primary_ssh, primary_public_ip, primary_ip, primary_id = connections[0], public_ips[0], private_ips[0], ids[0]
    with open(f'{BENCHMARK_NAME}-{SYSTEM}-{unique_str}-vm2.json') as f:
        vm_json = json.load(f)
        connections, public_ips, private_ips, ids = ssh_vm_json_plus(vm_json)
        benchmark_ssh, benchmark_public_ip, benchmark_ip, benchmark_id = connections[0], public_ips[0], private_ips[0], ids[0]

    # NEW: Launch the backup on GCP
    print("Launching the backup VM on GCP")
    PROJECT_ID="bigger-not-badder"
    ZONE="europe-west4-a"
    subprocess_execute([f"./launch_gcp.sh -i {primary_public_ip} -r {BENCHMARK_NAME}-{SYSTEM}-{unique_str} -p {PROJECT_ID} -z {ZONE}"])
    print("Connecting to the GCP VM")
    backup_ssh = connect_gcp_ssh(f"rollbaccine-backup.{ZONE}.{PROJECT_ID}")

    print("Installing rollbaccine on the primary")
    install_rollbaccine(ssh_executor, primary_ssh)
    print("Installing rollbaccine on the backup")
    install_rollbaccine(ssh_executor, backup_ssh)

    print("Setting up rollbaccine primary")
    GCP_DISK_SIZE = 786432000 # 375GB, since GCP's local SSDs are fixed at 375GB
    success = ssh_executor.exec(primary_ssh, [
        "sudo umount /dev/sdb1",
        "cd rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        f'echo "0 {GCP_DISK_SIZE} rollbaccine /dev/sdb 1 1 true abcdefghijklmnop 1 0 default 12340 false false 2" | sudo dmsetup create rollbaccine1',
    ])
    if not success:
        return False
    
    print("Setting up rollbaccine backup")
    # Note: Uses /dev/disk/by-id/google-local-nvme-ssd-0 instead of /dev/sdb according to GCP's convention
    success = ssh_executor.exec(backup_ssh, [
        "cd rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        f'echo "0 {GCP_DISK_SIZE} rollbaccine /dev/disk/by-id/google-local-nvme-ssd-0 2 1 false abcdefghijklmnop 1 0 default 12350 false false 1 {primary_public_ip} 12340" | sudo dmsetup create rollbaccine2'
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
        # Fix out-of-memory error
        "echo 'max_connections = 1024' | sudo tee -a /etc/postgresql/*/main/postgresql.conf",
        "echo 'max_locks_per_transaction = 1024' | sudo tee -a /etc/postgresql/*/main/postgresql.conf",
        "echo 'max_pred_locks_per_transaction = 1024' | sudo tee -a /etc/postgresql/*/main/postgresql.conf",
        # Trust all connections
        "echo 'host all all 0.0.0.0/0 trust' | sudo tee -a /etc/postgresql/*/main/pg_hba.conf",
        "sudo systemctl restart postgresql.service",
        "sudo -u postgres /usr/lib/postgresql/*/bin/createuser -s -i -d -r -l -w admin",
        "sudo -u postgres /usr/lib/postgresql/*/bin/createdb benchbase",
    ])
    if not success:
        return False

    print("Installing Benchbase on benchmarking VM, may also take a few minutes")
    success = ssh_executor.exec(benchmark_ssh, [
        "git clone --depth 1 https://github.com/davidchuyaya/benchbase",
        # Install Java
        "sudo apt-get -qq update",
        "sudo apt-get -y -qq install openjdk-21-jre",
        "cd benchbase",
        "./mvnw -q clean package -P postgres -DskipTests",
        "cd target",
        "tar xzf benchbase-postgres.tgz"
    ])
    if not success:
        return False
    
    print("Copying config file to benchmarking VM")
    REMOTE_CONFIG = "benchbase/target/benchbase-postgres/config/tpcc_config.xml"
    upload(benchmark_ssh, "src/tools/benchmarking/postgres/tpcc_config.xml", REMOTE_CONFIG)

    print("Modifying config file")
    success = ssh_executor.exec(benchmark_ssh, [f"sed -i 's/localhost/{primary_ip}/g' {REMOTE_CONFIG}"])
    if not success:
        return False

    print("Running TPCC, may take a few minutes")
    OUTPUT_DIR = f"/home/{getuser()}/results"
    for num_clients in range(20, 51, 10):
        success = ssh_executor.exec(benchmark_ssh, [
            "cd ~/benchbase/target/benchbase-postgres",
            f"sed -i -E 's~<terminals>.*</terminals>~<terminals>{num_clients}</terminals>~g' config/tpcc_config.xml",
            f"java -jar benchbase.jar -b tpcc -c config/tpcc_config.xml -d {OUTPUT_DIR} --clear=true --create=true --load=true --execute=true"
        ])
        if success:
            print(f"TPCC benchmark completed successfully for {num_clients} clients")
        else:
            print(f"TPCC benchmark failed")
            sys.exit(1)

    # Remove everything from the output_dir except summary.json, and rename summary.json
    success = ssh_executor.exec(benchmark_ssh, [
        f"cd {OUTPUT_DIR}",
        "rm -rf *.xml *.csv *.metrics.json *.params.json",
        f"ls | xargs -I {{}} mv {{}} {SYSTEM}_{unique_str}_{{}}"
    ])

    print("Downloading results")
    download_dir(benchmark_ssh, OUTPUT_DIR, "results")

    print("Benchmark completed, deleting resources")
    primary_ssh.close()
    backup_ssh.close()
    benchmark_ssh.close()
    subprocess_execute([f"./cleanup.sh -b {BENCHMARK_NAME} -s {SYSTEM} -e {unique_str}"])
    subprocess_execute(["./cleanup_gcp.sh"])

if __name__ == "__main__":
    run()