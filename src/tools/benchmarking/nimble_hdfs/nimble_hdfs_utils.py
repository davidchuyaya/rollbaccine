import os
import subprocess
import uuid
import itertools
import sys
import time
import threading
from dotenv import load_dotenv

# Add the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from benchmark import *
from utils import *

MOUNT_DIR = '/mnt/nimble-hdfs'
DATA_DIR = f"{MOUNT_DIR}/data"

ENDPOINT_PORT = 8082 # Must match port in hdfs-site.xml
COORDINATOR_PORT = 8080
ENDORSER_PORT = 9091

class NimbleHDFSBenchmark(Benchmark):
    def name(self):
        return "nimble-hdfs"
    
    def filename(self):
        return "nimble_hdfs/nimble_hdfs_utils.py"
    
    def num_vms(self):
        return 5 # 1 namenode, 1 coordinator, 3 endorsers
    
    def benchmarking_vm(self):
        return 0
    
    def install_nimble_on_vm(self, ssh: SSHClient):
        success = ssh_execute(ssh, [
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

    def install(self, username: str, connections: List[SSHClient], private_ips: List[str], system_type: System):
        name_node_ip = private_ips[self.benchmarking_vm()]
        name_node_ssh = connections[self.benchmarking_vm()]
        coordinator_ip = private_ips[1]
        coordinator_ssh = connections[1]
        endorser_ips = private_ips[2:5]
        endorser_sshs = connections[2:5]

        print(f"Checking if namenode has HDFS")
        if not is_installed(name_node_ssh, 'which hdfs'):
            print("Installing HDFS on the namenode, may take around 10 minutes")
            commands = mount_ext4_commands(mount_point(system_type), MOUNT_DIR)
            commands.extend([
                f"sudo mkdir -p {DATA_DIR}",
                f"sudo chown -R `whoami` {DATA_DIR}",
                "wget -nv https://github.com/IceCoooola/hadoop-nimble/archive/refs/tags/3.3.3.tar.gz",
                "mv 3.3.3.tar.gz hadoop-3.3.3.tar.gz",
                "tar -xzf hadoop-3.3.3.tar.gz",
                "sudo apt-get -qq update",
                "sudo apt-get -y -qq install openjdk-8-jre-headless",
                f"echo 'PATH=$PATH:/home/{username}/hadoop-3.3.3/bin' >> .profile",
                "echo 'export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64' >> .profile",
            ])
            
            success = ssh_execute(name_node_ssh, commands)
            if not success:
                return False
            
            print(f"Uploading configuration file")
            load_dotenv()
            CORE_SITE_PATH = os.path.join(os.getenv('BASE_PATH'), 'src', 'tools', 'benchmarking', 'nimble_hdfs', 'core-site.xml')
            HDFS_SITE_PATH = os.path.join(os.getenv('BASE_PATH'), 'src', 'tools', 'benchmarking', 'nimble_hdfs', 'hdfs-site.xml')
            upload(name_node_ssh, CORE_SITE_PATH, f'/home/{username}/hadoop-3.3.3/etc/hadoop/core-site.xml')
            upload(name_node_ssh, HDFS_SITE_PATH, f'/home/{username}/hadoop-3.3.3/etc/hadoop/hdfs-site.xml')

            # Replace {namenodeip} in core-site with the actual namenode IP
            print("Replacing {namenodeip} in core-site.xml")
            ssh_execute(name_node_ssh, [f"sed -i 's/{{namenodeip}}/{name_node_ip}/g' /home/{username}/hadoop-3.3.3/etc/hadoop/core-site.xml"])
            print("Replacing {nimbleip} in core-site.xml")
            ssh_execute(name_node_ssh, [f"sed -i 's/{{nimbleip}}/{coordinator_ip}/g' /home/{username}/hadoop-3.3.3/etc/hadoop/core-site.xml"])
            print(f"Finished installing HDFS")

        print("Installing Nimble on the coordinator and endorsers (in parallel)")
        threads = []
        for (i, ssh) in enumerate([coordinator_ssh] + endorser_sshs):
            if not is_installed(ssh, 'test -d Nimble && echo 1'):
                print(f"Installing Nimble on node {i}")
                thread = threading.Thread(target=self.install_nimble_on_vm, args=(ssh,))
                threads.append(thread)
                thread.start()
        for thread in threads:
            thread.join()
                
        # TODO: Don't put processes in the background, use another approach
        print("Starting the endorsers")
        for (i, ssh) in enumerate(endorser_sshs):
            print(f"Starting endorser {i}")
            success = ssh_execute(ssh, [
                "cd Nimble",
                f"target/release/endorser -p {ENDORSER_PORT} -t {endorser_ips[i]} &",
            ])
            if not success:
                return False
        
        # TODO: Switch from memory to Azure tables once this works 
        print("Starting the coordinator")
        success = ssh_execute(coordinator_ssh, [
            "cd Nimble",
            f"target/release/coordinator -t {coordinator_ip} -p {COORDINATOR_PORT} -e 'http://{endorser_ips[0]}:{ENDORSER_PORT},http://{endorser_ips[1]}:{ENDORSER_PORT},http://{endorser_ips[2]}:{ENDORSER_PORT}' -s 'memory'",
        ])
        if not success:
            return False
        
        print("Starting the endpoint (still on the coordinator)")
        success = ssh_execute(coordinator_ssh, [
            "cd Nimble",
            f"target/release/endpoint_rest -t {coordinator_ip} -p {ENDPOINT_PORT} -c 'http://{coordinator_ip}:{COORDINATOR_PORT}'",
        ])
        if not success:
            return False
        return True

    def run(self, username: str, system_type: System, output_dir: str):
        THREADS = 16
        FILES = 500000
        DIRS = 500000

        print("Starting the namenode")
        success = subprocess_execute(["hdfs namenode -format", "hdfs --daemon start namenode"])
        if not success:
            print("Failed to format and start the namenode")
            return False

        for op in ["create", "open", "delete", "fileStatus", "rename"]:
            print(f"Running {op}")
            success = subprocess_execute([f"hadoop org.apache.hadoop.hdfs.server.namenode.NNThroughputBenchmark -op {op} -threads {THREADS} -files {FILES} 2>&1 | tee {output_dir}/{system_type}_{op}.txt"])
            if not success:
                return False
            
        print(f"Running mkdirs")
        subprocess_execute([f"hadoop org.apache.hadoop.hdfs.server.namenode.NNThroughputBenchmark -op mkdirs -threads {THREADS} -dirs {DIRS} 2>&1 | tee {output_dir}/{system_type}_mkdirs.txt"])

        print(f"Cleaning up")
        subprocess_execute([f"hadoop org.apache.hadoop.hdfs.server.namenode.NNThroughputBenchmark -op clean"])
        
        return True  # Indicate success

if __name__ == "__main__":
    NimbleHDFSBenchmark().run(sys.argv[1], System[sys.argv[2]], sys.argv[3])