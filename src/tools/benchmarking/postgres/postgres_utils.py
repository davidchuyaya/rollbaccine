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

    def install(self, connections: List[SSHClient], private_ips: List[str], system_type: System, storage_name: str, storage_key: str):
        # Install Postgres on primary
        primary = connections[0]
        primary_private_ip = private_ips[0]
        if not is_installed(primary, 'which psql'):
            print("Installing Postgres on primary, may take a few minutes")
            success = ssh_execute(primary, [
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
            ])
            if not success:
                return False

        # Install Benchbase on the benchmarking VM
        benchbase = connections[self.benchmarking_vm()]
        if not is_installed(benchbase, "test -d benchbase-2023 && echo 1"):
            print("Installing Benchbase on benchmarking VM, may also take a few minutes")
            success = ssh_execute(benchbase, [
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
            upload(benchbase, "src/tools/benchmarking/postgres/tpcc_config.xml", REMOTE_CONFIG)

            print("Modifying config file")
            success = ssh_execute(benchbase, [f"sed -i 's/localhost/{primary_private_ip}/g' {REMOTE_CONFIG}"])
            if not success:
                return False
        return True

    def run(self, system_type: System, output_dir: str):
        print("Running TPCC, may take a few minutes")
        success = subprocess_execute([
            "cd ~/benchbase-2023/target/benchbase-postgres",
            f"java -jar benchbase.jar -b tpcc -c config/tpcc_config.xml -d {output_dir} --clear=true --create=true --load=true --execute=true"
        ])
        if success:
            print(f"TPCC benchmark completed successfully")
        else:
            print(f"TPCC benchmark failed")
            sys.exit(1)

if __name__ == "__main__":
    PostgresBenchmark().run(System[sys.argv[1]], sys.argv[2])