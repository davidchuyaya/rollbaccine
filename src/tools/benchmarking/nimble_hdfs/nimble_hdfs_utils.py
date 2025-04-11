import os
import sys
import threading
from getpass import getuser

# Add the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from benchmark import *
from utils import *

ENDPOINT_PORT = 8082 # Must match port in hdfs-site.xml
COORDINATOR_PORT = 8080
ENDORSER_PORT = 9091

class NimbleHDFSBenchmark(Benchmark):
    def __init__(self, batch_size, storage):
        self.storage = storage
        self.batch_size = batch_size
        if batch_size != 1 and batch_size != 100:
            print("Batch size must be 1 or 100")
            sys.exit(1)

    def filename(self):
        return "nimble_hdfs/nimble_hdfs_utils.py"
    
    def num_vms(self):
        return 4 # 1 namenode (colocated with the coordinator), 3 endorsers
    
    def benchmarking_vm(self):
        return 0
    
    def needs_storage(self) -> bool:
        return self.storage
    
    def install_nimble_on_vm(self, ssh_executor: SSH, ssh: SSHClient):
        success = ssh_executor.exec(ssh, [
            "git clone https://github.com/Microsoft/Nimble",
            "sudo apt-get -qq update",
            "sudo apt-get -y -qq install make gcc libssl-dev pkg-config perl protobuf-compiler",
            "curl -s --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y",
            "source $HOME/.cargo/env",
            "cd Nimble",
            "cargo build --release -q",
        ])
        if not success:
            return False

    def install(self, ssh_executor: SSH, connections: List[SSHClient], private_ips: List[str], system_type: System, storage_name: str, storage_key: str):
        name_node_ip = private_ips[self.benchmarking_vm()]
        name_node_ssh = connections[self.benchmarking_vm()]
        coordinator_ip = name_node_ip
        coordinator_ssh = name_node_ssh
        endorser_ips = private_ips[1:4]
        endorser_sshs = connections[1:4]

        print(f"Checking if namenode has HDFS")
        if not is_installed(name_node_ssh, 'which hdfs'):
            print("Installing HDFS on the namenode")
            success = ssh_executor.exec(name_node_ssh, [
                "wget -nv https://github.com/IceCoooola/hadoop-nimble/releases/download/3.3.3/hadoop-3.3.3.tar.gz",
                "tar -xzf hadoop-3.3.3.tar.gz",
                "sudo apt-get -qq update",
                "sudo apt-get -y -qq install openjdk-8-jre-headless",
                f"echo 'PATH=$PATH:/home/{getuser()}/hadoop-3.3.3/bin' >> .profile",
                "echo 'export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64' >> .profile",
            ])
            if not success:
                return False
            
            print(f"Uploading configuration file, batch size: {self.batch_size}")
            upload(name_node_ssh, f"src/tools/benchmarking/nimble_hdfs/core-site-{self.batch_size}.xml", f'/home/{getuser()}/hadoop-3.3.3/etc/hadoop/core-site.xml')
            upload(name_node_ssh, "src/tools/benchmarking/nimble_hdfs/hdfs-site.xml", f'/home/{getuser()}/hadoop-3.3.3/etc/hadoop/hdfs-site.xml')

            # Replace {namenodeip} in core-site with the actual namenode IP
            print("Replacing {namenodeip} in core-site.xml")
            ssh_executor.exec(name_node_ssh, [f"sed -i 's/{{namenodeip}}/{name_node_ip}/g' /home/{getuser()}/hadoop-3.3.3/etc/hadoop/core-site.xml"])
            # print("Replacing {nimbleip} in core-site.xml")
            # ssh_executor.exec(name_node_ssh, [f"sed -i 's/{{nimbleip}}/{coordinator_ip}/g' /home/{getuser()}/hadoop-3.3.3/etc/hadoop/core-site.xml"])
            print(f"Finished installing HDFS")

        print("Installing Nimble on the coordinator and endorsers (in parallel)")
        threads = []
        for (i, ssh) in enumerate([coordinator_ssh] + endorser_sshs):
            if not is_installed(ssh, 'test -d Nimble && echo 1'):
                print(f"Installing Nimble on node {i}")
                thread = threading.Thread(target=self.install_nimble_on_vm, args=(ssh_executor, ssh,))
                threads.append(thread)
                thread.start()
        for thread in threads:
            thread.join()
                
        print("Starting the endorsers")
        for (i, ssh) in enumerate(endorser_sshs):
            print(f"Starting endorser {i}")
            success = ssh_execute_background(ssh, [
                "cd Nimble",
                f"target/release/endorser -p {ENDORSER_PORT} -t {endorser_ips[i]}",
            ])

        print("Starting the coordinator")
        if self.storage:
            storage_params = f"-s 'table' -n nimbledb -a {storage_name} -k {storage_key}"
        else:
            storage_params = "-s 'memory'"
        ssh_execute_background(coordinator_ssh, [
            "cd Nimble",
            f"target/release/coordinator -t 127.0.0.1 -p {COORDINATOR_PORT} -e 'http://{endorser_ips[0]}:{ENDORSER_PORT},http://{endorser_ips[1]}:{ENDORSER_PORT},http://{endorser_ips[2]}:{ENDORSER_PORT}' {storage_params}",
        ])
        
        print("Starting the endpoint (still on the coordinator)")
        success = ssh_execute_background(coordinator_ssh, [
            "cd Nimble",
            f"target/release/endpoint_rest -t 127.0.0.1 -p {ENDPOINT_PORT} -c 'http://127.0.0.1:{COORDINATOR_PORT}'",
        ])
        
        return True

    # Note: We ignore extra_args in this function since it's only used for Rollbaccine, which is not compatible with NimbleHDFS
    def run(self, system_type: System, mount_point: str, output_dir: str, extra_args: str):
        THREADS = 16
        # Use fewer files and directories since Nimble is very slow
        if self.batch_size == 1:
            FILES = 10000
            DIRS = 10000
        else:
            FILES = 100000
            DIRS = 100000

        print("Starting the namenode")
        success = subprocess_execute(["hdfs namenode -format", "hdfs --daemon start namenode"])
        if not success:
            print("Failed to format and start the namenode")
            sys.exit(1)
            return

        for i in range(0, NUM_REPETITIONS):
            print(f"Round {i}")
            for op in ["create", "open", "delete", "fileStatus", "rename"]:
                print(f"Running {op}")
                success = subprocess_execute([f"hadoop org.apache.hadoop.hdfs.server.namenode.NNThroughputBenchmark -op {op} -threads {THREADS} -files {FILES} 2>&1 | tee {output_dir}/NIMBLE_HDFS_{self.batch_size}_{self.storage}_{op}_{i}.txt"])
                if not success:
                    sys.exit(1)
                    return
                
            print(f"Running mkdirs")
            subprocess_execute([f"hadoop org.apache.hadoop.hdfs.server.namenode.NNThroughputBenchmark -op mkdirs -threads {THREADS} -dirs {DIRS} 2>&1 | tee {output_dir}/NIMBLE_HDFS_{self.batch_size}_{self.storage}_mkdirs_{i}.txt"])

            print(f"Cleaning up")
            subprocess_execute([f"hadoop org.apache.hadoop.hdfs.server.namenode.NNThroughputBenchmark -op clean"])

if __name__ == "__main__":
    batch_size = int(sys.argv[4])
    storage = sys.argv[5] == "True"
    NimbleHDFSBenchmark(batch_size, storage).run(System[sys.argv[1]], sys.argv[2], sys.argv[3], "")