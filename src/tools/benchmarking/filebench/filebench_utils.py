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

    def install(self, username: str, connections: List[SSHClient], private_ips: List[str], system_type: System):
        ssh = connections[self.benchmarking_vm()]
        if not is_installed(ssh, 'which filebench'):
            print("Installing Filebench, may take a few minutes")
            success = ssh_execute(ssh, [
                "wget -nv https://github.com/filebench/filebench/releases/download/1.5-alpha3/filebench-1.5-alpha3.tar.gz",
                "tar -xf filebench-1.5-alpha3.tar.gz",
                "cd filebench-1.5-alpha3",
                # Filebench needs to be modified to allow mail-server.f and web-server.f to load so many files: https://github.com/filebench/filebench/issues/90
                r"sed -i 's/FILEBENCH_NFILESETENTRIES\t(1024 \* 1024)/FILEBENCH_NFILESETENTRIES\t(1024 * 1024 * 10)/g' ipc.h",
                # Modification to avoid buffer overflow error.
                r"sed -i 's/s = malloc(strlen(path) + 1);/s = malloc(MAXPATHLEN);/g' fileset.c",
                # Install dependencies: https://github.com/filebench/filebench/wiki/Building-Filebench#building-filebench-from-the-git-repository
                "sudo apt-get -qq update",
                "sudo apt-get -qq -y install bison flex build-essential",
                "./configure",
                "make --silent",
                "sudo make --silent install"
            ])
            if not success:
                return False
        return True

    def run(self, username: str, system_type: System, output_dir: str):
        # See issue: https://github.com/filebench/filebench/issues/112
        subprocess_execute(["echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"])

        for file_system in ['ext4', 'xfs']:
            unmount = [f"sudo umount -q {MOUNT_DIR}"]
            mount = mount_commands(file_system, mount_point(system_type), MOUNT_DIR)

            print(f"Mounting {file_system}")
            subprocess_execute(mount, silent=True)

            print(f"Running Filebench varmail over {file_system}, will take 60 seconds")
            subprocess_execute([rf"sudo filebench -f /home/{username}/rollbaccine/src/tools/benchmarking/filebench/varmail.f 2>&1 | tee {output_dir}/{system_type}_{file_system}_varmail.txt"])

            print("Unmounting and remounting before next experiment")
            subprocess_execute(unmount + mount, silent=True)

            print(f"Running Filebench webserver over {file_system}, will take 60 seconds")
            subprocess_execute([rf"sudo filebench -f /home/{username}/rollbaccine/src/tools/benchmarking/filebench/webserver.f 2>&1 | tee {output_dir}/{system_type}_{file_system}_webserver.txt"])
            subprocess_execute(unmount, silent=True)
        return True  # Indicate success

if __name__ == "__main__":
    FileBenchmark().run(sys.argv[1], System[sys.argv[2]], sys.argv[3])