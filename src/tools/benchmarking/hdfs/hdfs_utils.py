import os
import subprocess
import uuid
import itertools
import sys
import time

# Add the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from benchmark import *
from utils import *

MOUNT_DIR = '/mnt/hdfs'
DATA_DIR = f"{MOUNT_DIR}/data"
CORE_SITE_PATH = os.path.join(os.getenv('BASE_PATH'), 'src', 'tools', 'benchmarking', 'hdfs', 'core-site.xml')
HDFS_SITE_PATH = os.path.join(os.getenv('BASE_PATH'), 'src', 'tools', 'benchmarking', 'hdfs', 'hdfs-site.xml')

class HDFSBenchmark(Benchmark):
    def name(self):
        return "hdfs"
    
    def filename(self):
        return "hdfs/hdfs_utils.py"
    
    def num_vms(self):
        return 2 # Namenode, Datanode
    
    def benchmarking_vm(self):
        return 0 # Run NNThroughputBenchmark on the namenode

    def install(self, username: str, connections: List[SSHClient], private_ips: List[str], system_type: System):
        name_node_ip = private_ips[self.benchmarking_vm()]

        print("Installing HDFS on both namenode and datanode, may take a few minutes")
        for (i, ssh) in enumerate(connections):
            if not is_installed(ssh, 'which hdfs'):
                print(f"Installing HDFS on node {i}")
                commands = mount_ext4_commands(mount_point(system_type), MOUNT_DIR)
                commands.extend([
                    f"sudo chown -R `whoami` {MOUNT_DIR}",
                    "wget https://archive.apache.org/dist/hadoop/common/hadoop-3.3.3/hadoop-3.3.3.tar.gz",
                    "tar -xzvf hadoop-3.3.3.tar.gz",
                    "sudo apt-get update",
                    "sudo apt-get -y install openjdk-8-jdk",
                    "echo 'export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64' | sudo tee -a /etc/environment",
                    f"echo 'PATH=$PATH:/home/{username}/hadoop-3.3.3/bin' | sudo tee -a /etc/environment",
                    "source /etc/environment",
                ])
                success = ssh_execute(ssh, commands)
                if not success:
                    return False
                
                upload(ssh, CORE_SITE_PATH, f'/home/{username}/hadoop-3.3.3/etc/hadoop/core-site.xml')
                upload(ssh, HDFS_SITE_PATH, f'/home/{username}/hadoop-3.3.3/etc/hadoop/hdfs-site.xml')

                # Replace {namenodeip} in core-site with the actual namenode IP
                subprocess_execute([f"sed -i 's/{{namenodeip}}/{name_node_ip}/g' /home/{username}/hadoop-3.3.3/etc/hadoop/core-site.xml"])

                # Start the node
                if i == 0:
                    success = ssh_execute(ssh, [
                        "hdfs namenode -format",
                        "hdfs --daemon start namenode"
                    ])
                    if not success:
                        return False
                else:
                    success = ssh_execute(ssh, [
                        "hdfs --daemon start datanode"
                    ])
                    if not success:
                        return False

                print(f"Finished installing and starting HDFS on node {i}")

        return True

    def run(self, username: str, system_type: System, output_dir: str):
        THREADS = 16
        FILES = 500000
        DIRS = 500000

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
    HDFSBenchmark().run(sys.argv[1], System[sys.argv[2]], sys.argv[3])