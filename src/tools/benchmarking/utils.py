from paramiko import SSHClient
from typing import List
from collections import deque
from benchmark import *
import subprocess
import sys
import time
from rich.live import Live
from rich.table import Table

COLOR_UNIMPORTANT = '\033[90m'
COLOR_ERROR = '\033[91m'
COLOR_END = '\033[0m'

def is_installed(ssh: SSHClient, command: str) -> bool:
    """
    Returns whether the given command produces an output or not
    """
    stdin, stdout, stderr = ssh.exec_command(command)
    path = stdout.read().decode().strip()
    return path != ''

def ssh_execute(ssh: SSHClient, commands: List[str], silent=False) -> bool:
    # Make sure we source the environment variables placed in .profile first
    commands.insert(0, "source .profile")
    # Join commands with "&&" so we can use "cd" correctly
    separator = " && "
    combined_commands = separator.join(commands)
    stdin, stdout, stderr = ssh.exec_command(combined_commands, get_pty=True)
    if not silent:
        # Continuously print the last 10 lines, updating every second. Updating too fast means it won't work.
        buffer = deque(maxlen=10)
        table = Table()
        table.add_column("Output")
        with Live(table, refresh_per_second=10) as live:
            for line in iter(stdout.readline, ""):
                buffer.append(line.strip())
                table.rows.clear()
                for line in buffer:
                    table.add_row(line)

    error = stderr.read().decode()
    if error:
        print(f"Error executing commands: {commands}")
        print(f"{COLOR_ERROR}{error}{COLOR_END}")
        return False
    return True

def subprocess_execute(commands: List[str], silent=False) -> bool:
    separator = " && "
    combined_commands = separator.join(commands)
    process = subprocess.Popen(combined_commands, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in process.stdout:
        print(line)
    if process.returncode != 0:
        print(f"Error executing commands: {commands}")
        for line in process.stderr:
            print(f"{COLOR_ERROR}{line}{COLOR_END}")
        return False
    return True

def upload(ssh: SSHClient, local_path: str, remote_path: str):
    sftp = ssh.open_sftp()
    sftp.put(local_path, remote_path, confirm=False)
    sftp.close()

def download(ssh: SSHClient, remote_path: str, local_path: str):
    sftp = ssh.open_sftp()
    sftp.get(remote_path, local_path)
    sftp.close()

def download_dir(ssh: SSHClient, remote_dir: str, local_dir: str):
    """
    Download all files from a remote directory to a local directory
    Note: Does not handle nested directories
    """
    sftp = ssh.open_sftp()
    for filename in sftp.listdir(remote_dir):
        remote_path = f"{remote_dir}/{filename}"
        local_path = f"{local_dir}/{filename}"
        sftp.get(remote_path, local_path)
    sftp.close()

def mount_point(system_type: System) -> str:
    """
    The file that represents the system configuration.
    """
    if system_type == System.UNREPLICATED:
        return '/dev/sdb1'
    elif system_type == System.DM:
        return '/dev/mapper/secure' 
    elif system_type == System.REPLICATED:
        return '/dev/sda'
    elif system_type == System.ROLLBACCINE:
        return '/dev/mapper/rollbaccine1'

def mount_commands(file_system: str, mount_path: str, new_dir: str) -> List[str]:
    # Flag to force mounting file system is -F for ext4 and -f for xfs
    force_flag = '-F' if file_system == 'ext4' else '-f'
    return [
        f"sudo mkfs.{file_system} {force_flag} {mount_path}",
        f"sudo mkdir -p {new_dir}",
        f"sudo mount {mount_path} {new_dir}",
    ]

def mount_ext4_commands(mount_path: str, new_dir: str) -> List[str]:
    return mount_commands('ext4', mount_path, new_dir)

def mount_xfs_commands(mount_path: str, new_dir: str) -> List[str]:
    return mount_commands('xfs', mount_path, new_dir)