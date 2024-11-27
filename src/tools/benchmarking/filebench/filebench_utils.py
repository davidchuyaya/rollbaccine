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

MOUNT_DIR = '/mnt/filebench'
DATA_DIR = f"{MOUNT_DIR}/data"

class FileBenchmark(Benchmark):
    def name(self):
        return "filebench"
    
    def filename(self):
        return "filebench/filebench_utils.py"
    
    def num_vms(self):
        return 1
    
    def benchmarking_vm(self):
        return 0

    def install(self, connections: List[SSHClient], private_ips: List[str], system_type: System):
        ssh = connections[self.benchmarking_vm()]
        if not is_installed(ssh, 'which filebench'):
            print("Installing Filebench, may take a few minutes")
            success = ssh_execute(ssh, [
                "wget https://github.com/filebench/filebench/releases/download/1.5-alpha3/filebench-1.5-alpha3.tar.gz",
                "tar -xvf filebench-1.5-alpha3.tar.gz",
                "cd filebench-1.5-alpha3",
                # Filebench needs to be modified to allow mail-server.f and web-server.f to load so many files: https://github.com/filebench/filebench/issues/90
                r"sed -i 's/FILEBENCH_NFILESETENTRIES\t(1024 \* 1024)/FILEBENCH_NFILESETENTRIES\t(1024 * 1024 * 10)/g' ipc.h",
                # Install dependencies: https://github.com/filebench/filebench/wiki/Building-Filebench#building-filebench-from-the-git-repository
                "sudo apt-get update",
                "sudo apt-get -y install bison flex build-essential",
                "./configure",
                "make",
                "sudo make install"
            ])
            if not success:
                return False
        return True

    def run(self, username: str, system_type: System, output_dir: str):
        for file_system in ['ext4', 'xfs']:
            print(f"Mounting {file_system}")
            subprocess_execute(mount_commands(file_system, mount_point(system_type), MOUNT_DIR), silent=True)

            print(f"Running Filebench varmail over {file_system}, may take a few minutes")
            subprocess_execute([f"sudo filebench -f /home/{username}/rollbaccine/src/tools/benchmarking/filebench/varmail.f \|& tee {output_dir}/{system_type}_{file_system}_varmail.txt"])

            print("Unmounting and remounting before next experiment")
            subprocess_execute([f"sudo umount {MOUNT_DIR}"])
            subprocess_execute(mount_commands(file_system, mount_point(system_type), MOUNT_DIR), silent=True)

            print(f"Running Filebench webserver over {file_system}, may take a few minutes")
            subprocess_execute([f"sudo filebench -f /home/{username}/rollbaccine/src/tools/benchmarking/filebench/webserver.f \|& tee {output_dir}/{system_type}_{file_system}_webserver.txt"])
        return True  # Indicate success

if __name__ == "__main__":
    FileBenchmark().run(sys.argv[1], System[sys.argv[2]], sys.argv[3])