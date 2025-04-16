import os
import sys
from getpass import getuser

# Add the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from benchmark import *
from utils import *

class PostgresBenchmark(Benchmark):
    def filename(self):
        return "postgres/postgres_utils.py"
    
    def num_vms(self):
        return 2
    
    def benchmarking_vm(self):
        return 1 # Don't run benchmarking on the primary
    
    def needs_storage(self) -> bool:
        return False

    def install(self, ssh_executor: SSH, connections: List[SSHClient], private_ips: List[str], system_type: System, storage_name: str, storage_key: str):
        # Install Postgres on primary
        primary = connections[0]
        primary_private_ip = private_ips[0]
        if not is_installed(primary, 'which psql'):
            print("Installing Postgres on primary, may take a few minutes")
            success = ssh_executor.exec(primary, [
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

        # Install Benchbase on the benchmarking VM
        benchbase = connections[self.benchmarking_vm()]
        if not is_installed(benchbase, "test -d benchbase && echo 1"):
            print("Installing Benchbase on benchmarking VM, may also take a few minutes")
            success = ssh_executor.exec(benchbase, [
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
            upload(benchbase, "src/tools/benchmarking/postgres/tpcc_config.xml", REMOTE_CONFIG)

            print("Modifying config file")
            success = ssh_executor.exec(benchbase, [f"sed -i 's/localhost/{primary_private_ip}/g' {REMOTE_CONFIG}"])
            if not success:
                return False
        return True

    def run(self, system_type: System, mount_point: str, output_dir: str, extra_args: str):
        print("Running TPCC, may take a few minutes")
        for num_clients in range(20, 51, 10):
            success = subprocess_execute([
                "cd ~/benchbase/target/benchbase-postgres",
                f"sed -i -E 's~<terminals>.*</terminals>~<terminals>{num_clients}</terminals>~g' config/tpcc_config.xml",
                f"java -jar benchbase.jar -b tpcc -c config/tpcc_config.xml -d {output_dir} --clear=true --create=true --load=true --execute=true"
            ])
            if success:
                print(f"TPCC benchmark completed successfully for {num_clients} clients")
            else:
                print(f"TPCC benchmark failed")
                sys.exit(1)

        # Remove everything from the output_dir except summary.json, and rename summary.json
        success = subprocess_execute([
            f"cd {output_dir}",
            "rm -rf *.xml *.csv *.metrics.json *.params.json",
            f"ls | xargs -I {{}} mv {{}} {system_type}_{extra_args}_{{}}"
        ])

if __name__ == "__main__":
    PostgresBenchmark().run(System[sys.argv[1]], sys.argv[2], sys.argv[3], sys.argv[4])