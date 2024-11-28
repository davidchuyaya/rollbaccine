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

MOUNT_DIR = '/mnt/hdfs'
DATA_DIR = f"{MOUNT_DIR}/data"

class HDFSBenchmark(Benchmark):
    def name(self):
        return "hdfs"
    
    def filename(self):
        return "hdfs/hdfs_utils.py"
    
    def num_vms(self):
        return 1
    
    def benchmarking_vm(self):
        return 0

    def install(self, username: str, connections: List[SSHClient], private_ips: List[str], system_type: System):
        name_node_ip = private_ips[self.benchmarking_vm()]
        ssh = connections[self.benchmarking_vm()]

        print("Installing HDFS, may take a few minutes")
        if not is_installed(ssh, 'which hdfs'):
            commands = mount_ext4_commands(mount_point(system_type), MOUNT_DIR)
            commands.extend([
                f"sudo mkdir -p {DATA_DIR}",
                f"sudo chown -R `whoami` {DATA_DIR}",
                "wget https://mirror.lyrahosting.com/apache/hadoop/core/hadoop-3.3.3/hadoop-3.3.3.tar.gz",
                "tar -xzf hadoop-3.3.3.tar.gz",
                "sudo apt-get update",
                "sudo apt-get -y install openjdk-8-jre-headless",
                f"echo 'PATH=$PATH:/home/{username}/hadoop-3.3.3/bin' >> .profile",
                "echo 'export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64' >> .profile"
            ])
            
            success = ssh_execute(ssh, commands)
            if not success:
                return False
            
            print(f"Uploading configuration file")
            load_dotenv()
            CORE_SITE_PATH = os.path.join(os.getenv('BASE_PATH'), 'src', 'tools', 'benchmarking', 'hdfs', 'core-site.xml')
            HDFS_SITE_PATH = os.path.join(os.getenv('BASE_PATH'), 'src', 'tools', 'benchmarking', 'hdfs', 'hdfs-site.xml')
            upload(ssh, CORE_SITE_PATH, f'/home/{username}/hadoop-3.3.3/etc/hadoop/core-site.xml')
            upload(ssh, HDFS_SITE_PATH, f'/home/{username}/hadoop-3.3.3/etc/hadoop/hdfs-site.xml')

            # Replace {namenodeip} in core-site with the actual namenode IP
            print("Replacing {namenodeip} in core-site.xml")
            ssh_execute(ssh, [f"sed -i 's/{{namenodeip}}/{name_node_ip}/g' /home/{username}/hadoop-3.3.3/etc/hadoop/core-site.xml"])
            print(f"Finished installing HDFS")
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
    HDFSBenchmark().run(sys.argv[1], System[sys.argv[2]], sys.argv[3])