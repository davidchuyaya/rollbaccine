import os
import subprocess
import uuid
import itertools
import sys
import time
from dotenv import load_dotenv

# Add the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from benchmark import *
from utils import *

MOUNT_DIR = '/mnt/postgres'
DATA_DIR = f"{MOUNT_DIR}/data"

class PostgresBenchmark(Benchmark):
    def name(self):
        return "postgres"
    
    def filename(self):
        return "postgres/postgres_utils.py"
    
    def num_vms(self):
        return 2
    
    def benchmarking_vm(self):
        return 1 # Don't run benchmarking on the primary

    def install(self, username: str, connections: List[SSHClient], private_ips: List[str], system_type: System):
        # Install Postgres on primary
        primary = connections[0]
        primary_private_ip = private_ips[0]
        if not is_installed(primary, 'which psql'):
            print("Installing Postgres on primary, may take a few minutes")
            commands = mount_ext4_commands(mount_point(system_type), MOUNT_DIR)
            commands.extend([
                "sudo apt-get update",
                "sudo apt-get install -y postgresql-common",
                # Install to our custom directory
                f"echo 'data_directory = '\'{DATA_DIR}\' | sudo tee -a /etc/postgresql-common/createcluster.conf",
                f"sudo mkdir -p {DATA_DIR}",
                f"sudo chown -R postgres:postgres {DATA_DIR}",
                "sudo apt-get install -y postgresql",
                # Listens to public addresses
                "echo 'listen_addresses = '\'*\' | sudo tee -a /etc/postgresql/*/main/postgresql.conf",
                # Trust all connections
                "echo 'host all all 0.0.0.0/0 trust' | sudo tee -a /etc/postgresql/*/main/pg_hba.conf",
                "sudo systemctl restart postgresql.service",
                "sudo -u postgres /usr/lib/postgresql/*/bin/createuser -s -i -d -r -l -w admin",
                "sudo -u postgres /usr/lib/postgresql/*/bin/createdb benchbase",
            ])
            success = ssh_execute(primary, commands)
            if not success:
                return False

        # Install Benchbase on the benchmarking VM
        benchbase = connections[self.benchmarking_vm()]
        if not is_installed(benchbase, "test -d benchbase && echo 1"):
            print("Installing Benchbase on benchmarking VM, may also take a few minutes")
            success = ssh_execute(benchbase, [
                "wget https://github.com/cmu-db/benchbase/archive/refs/tags/v2023.tar.gz"
                "tar -xvzf v2023.tar.gz",
                # Install Java
                "sudo apt-get update",
                "sudo apt-get -y install openjdk-21-jdk",
                "cd benchbase-2023",
                "./mvnw clean package -P postgres -DskipTests",
                "cd target",
                "tar xvzf benchbase-postgres.tgz"
            ])
            if not success:
                return False
            
            print("Copying config file to benchmarking VM")
            load_dotenv()
            TPCC_CONFIG = os.path.join(os.getenv('BASE_PATH'), 'src', 'tools', 'benchmarking', 'postgres', 'tpcc_config.json')
            REMOTE_CONFIG = "benchbase-2023/target/benchbase-postgres/config/tpcc_config.json"
            upload(benchbase, TPCC_CONFIG, REMOTE_CONFIG)

            print("Modifying config file")
            success = ssh_execute(benchbase, [
                f"sed -i 's/localhost/{primary_private_ip}/g' {REMOTE_CONFIG}"
            ])
            if not success:
                return False
        return True

    def run(self, username: str, system_type: System, output_dir: str):
        os.chdir("benchbase-2023/target/benchbase-postgres")

        print("Running TPCC, may take a few minutes")
        success = subprocess_execute([
            "cd benchbase-2023/target/benchbase-postgres",
            f"java -jar benchbase.jar -b tpcc -c config/tpcc_config.json -d {output_dir} --clear=true --create=true --load=true --execute=true"
        ])

        if success:
            print(f"TPCC benchmark completed successfully")
        else:
            print(f"TPCC benchmark failed")

        return success

if __name__ == "__main__":
    PostgresBenchmark().run(sys.argv[1], System[sys.argv[2]], sys.argv[3])