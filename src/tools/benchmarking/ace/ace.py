import os
import sys
import time
from getpass import getuser

# Add the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from run_benchmarks import *
from benchmark import *
from utils import *

# Must match modify_tests.sh, which was used to generate the ACE tests we download here:
# https://github.com/davidchuyaya/crashmonkey/releases/download/rollbaccine/seq1_nested.tar.gz
BACKUP_MOUNT_DIR = "/mnt/newfsbackup"

# Mostly copied from run_benchmarks:run_everything
def run():
    # Create resources
    BENCHMARK_NAME = "fio"
    SYSTEM = System.UNREPLICATED
    print(f"Creating a VM under '{BENCHMARK_NAME}' benchmark and '{SYSTEM}' system, because we just want a single VM.")
    subprocess_execute([f"./launch.sh -b fio -s {SYSTEM} -n 1"])
    ssh_executor = SSH("ace")

    print("Connecting to VMs and setting up main VMs")
    print(f"\033[92mPlease run `tail -f {ssh_executor.output_file}` to see the execution log on the servers.\033[0m")
    ssh_executor.clear_output_file()
    
    with open('vm1.json') as f:
        vm_json = json.load(f)
        connections, private_ips = ssh_vm_json(vm_json)
        ssh = connections[0]
    
    print("Installing rollbaccine")
    install_rollbaccine(ssh)

    print("Setting up rollbaccine primary and backup each over a 10GB ramdisk (so it can run faster)")
    success = ssh_executor.exec(ssh, [
        "sudo modprobe brd rd_nr=2 rd_size=10485760",
        "cd rollbaccine/src",
        "sudo insmod rollbaccine.ko",
        'echo "0 $(sudo blockdev --getsz /dev/ram0) rollbaccine /dev/ram0 1 2 0 true 250000 abcdefghijklmnop 12340" | sudo dmsetup create rollbaccine1',
        'echo "0 $(sudo blockdev --getsz /dev/ram1) rollbaccine /dev/ram1 1 2 1 false 250000 abcdefghijklmnop 12350 127.0.0.1 12340" | sudo dmsetup create rollbaccine2'
    ])
    if not success:
        return False
    
    print("Waiting 10 seconds for rollbaccine to finish setup")
    sleep(10)

    print("Mounting /dev/sdb1 at /mnt/test. It won't be used in the test but xfstests will check")
    success = ssh_executor.exec(ssh, [
        "sudo umount /dev/sdb1",
        "sudo mkfs.ext4 -F /dev/sdb1",
        "sudo mkdir -p /mnt/test",
        "sudo mount /dev/sdb1 /mnt/test"
    ])
    if not success:
        return False

    print(f"Creating a mount point for the primary at {MOUNT_DIR} and backup at {BACKUP_MOUNT_DIR}")
    success = ssh_executor.exec(ssh, [f"sudo mkdir -p {MOUNT_DIR} {BACKUP_MOUNT_DIR}"])
    if not success:
        return False

    print("Installing xfstests, will take a few minutes")
    success = ssh_executor.exec(ssh, [
        "sudo apt-get -qq install acl attr automake bc dbench dump e2fsprogs fio gawk \
        gcc git indent libacl1-dev libaio-dev libcap-dev libgdbm-dev libtool \
        libtool-bin liburing-dev libuuid1 lvm2 make psmisc python3 quota sed \
        uuid-dev uuid-runtime xfsprogs linux-headers-$(uname -r) sqlite3 \
        libgdbm-compat-dev xfsdump xfslibs-dev exfatprogs",
        "git clone -q git://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git",
        "cd xfstests-dev",
        "make --silent",
        "sudo make --silent install"
    ])
    if not success:
        return False
    
    print("Setting up xfstests")
    success = ssh_executor.exec(ssh, [
        "cd xfstests-dev/tests",
        "wget -nv https://github.com/davidchuyaya/crashmonkey/releases/download/rollbaccine/seq1_nested.tar.gz",
        "tar -xzf seq1_nested.tar.gz",
        "cd ..",
        "cp ~/rollbaccine/src/tools/benchmarking/ace/local.config ."
    ])
    if not success:
        return False

    print("Running xfstests, will take around 4 minutes")
    OUTPUT_DIR = f"/home/{getuser()}/results"
    success = ssh_executor.exec(ssh, [
        f"mkdir -p {OUTPUT_DIR}",
        "cd xfstests-dev",
        f"sudo ./check -g seq1_nested/auto 2>&1 | tee {OUTPUT_DIR}/xfstests.txt"
    ])
    if not success:
        return False

    print("Downloading results")
    download_dir(ssh, OUTPUT_DIR, ".")
    ssh.close()

    print("Benchmark completed, deleting resources")
    subprocess_execute([f"./cleanup.sh -b {BENCHMARK_NAME} -s {SYSTEM}"])

if __name__ == "__main__":
    run()