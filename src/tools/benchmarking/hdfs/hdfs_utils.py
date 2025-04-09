import os
import sys
from getpass import getuser

# Add the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from benchmark import *
from utils import *

class HDFSBenchmark(Benchmark):
    def filename(self):
        return "hdfs/hdfs_utils.py"
    
    def num_vms(self):
        return 1
    
    def benchmarking_vm(self):
        return 0
    
    def needs_storage(self) -> bool:
        return False

    def install(self, ssh_executor: SSH, connections: List[SSHClient], private_ips: List[str], system_type: System, storage_name: str, storage_key: str):
        name_node_ip = private_ips[self.benchmarking_vm()]
        ssh = connections[self.benchmarking_vm()]

        print("Installing HDFS, may take a few minutes")
        if not is_installed(ssh, 'which hdfs'):
            success = ssh_executor.exec(ssh, [
                "wget -nv https://mirror.lyrahosting.com/apache/hadoop/core/hadoop-3.3.3/hadoop-3.3.3.tar.gz",
                "tar -xzf hadoop-3.3.3.tar.gz",
                "sudo apt-get -qq update",
                "sudo apt-get -y -qq install openjdk-8-jre-headless",
                f"echo 'PATH=$PATH:/home/{getuser()}/hadoop-3.3.3/bin' >> .profile",
                "echo 'export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64' >> .profile"
            ])
            if not success:
                return False
            
            print(f"Uploading configuration file")
            upload(ssh, "src/tools/benchmarking/hdfs/core-site.xml", f'/home/{getuser()}/hadoop-3.3.3/etc/hadoop/core-site.xml')
            upload(ssh, "src/tools/benchmarking/hdfs/hdfs-site.xml", f'/home/{getuser()}/hadoop-3.3.3/etc/hadoop/hdfs-site.xml')

            # Replace {namenodeip} in core-site with the actual namenode IP
            print("Replacing {namenodeip} in core-site.xml")
            ssh_executor.exec(ssh, [f"sed -i 's/{{namenodeip}}/{name_node_ip}/g' /home/{getuser()}/hadoop-3.3.3/etc/hadoop/core-site.xml"])
            print(f"Finished installing HDFS")
        return True

    def run(self, system_type: System, mount_point: str, output_dir: str, extra_args: str):
        THREADS = 16
        FILES = 500000
        DIRS = 500000

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
                success = subprocess_execute([f"hadoop org.apache.hadoop.hdfs.server.namenode.NNThroughputBenchmark -op {op} -threads {THREADS} -files {FILES} 2>&1 | tee {output_dir}/{system_type}_{extra_args}_{op}_{i}.txt"])
                if not success:
                    sys.exit(1)
                    return
                
            print(f"Running mkdirs")
            subprocess_execute([f"hadoop org.apache.hadoop.hdfs.server.namenode.NNThroughputBenchmark -op mkdirs -threads {THREADS} -dirs {DIRS} 2>&1 | tee {output_dir}/{system_type}_{extra_args}_mkdirs_{i}.txt"])

            print(f"Cleaning up")
            subprocess_execute([f"hadoop org.apache.hadoop.hdfs.server.namenode.NNThroughputBenchmark -op clean"])

if __name__ == "__main__":
    HDFSBenchmark().run(System[sys.argv[1]], sys.argv[2], sys.argv[3], sys.argv[4])