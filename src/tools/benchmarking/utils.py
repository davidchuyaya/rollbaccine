from paramiko import SSHClient
from typing import List
from collections import deque
from benchmark import *
import subprocess
import sys
import time

OUTPUT_FILE = "stdout.txt"
COLOR_UNIMPORTANT = '\033[90m'
COLOR_ERROR = '\033[91m'
COLOR_END = '\033[0m'

def is_installed(ssh: SSHClient, command: str) -> bool:
    """
    Returns whether the given command produces an output or not
    """
    stdin, stdout, stderr = ssh.exec_command("source .profile && " + command)
    path = stdout.read().decode().strip()
    return path != ''

def clear_output_file():
    open(OUTPUT_FILE, 'w').close()

def ssh_execute(ssh: SSHClient, commands: List[str], silent=False) -> bool:
    """
    Execute a list of commands on an SSH connection.
    DO NOT pass a string into commands!
    """
    # Make sure we source the environment variables placed in .profile first
    commands.insert(0, "source .profile")
    # Join commands with "&&" so we can use "cd" correctly
    separator = " && "
    combined_commands = separator.join(commands)
    stdin, stdout, stderr = ssh.exec_command(combined_commands, get_pty=True)
    # Write outputs to OUTPUT_FILE
    if not silent:
        with open(OUTPUT_FILE, "a") as stdout_file:
            for line in stdout:
                stdout_file.write(line)
                stdout_file.flush()
            
    error = stderr.read().decode()
    if error:
        print(f"Error executing SSH commands: {combined_commands}")
        print(f"{COLOR_ERROR}{error}{COLOR_END}")
        return False
    return True

def ssh_execute_background(ssh: SSHClient, commands: List[str]):
    """
    Execute the last command in a list of commands on an SSH connection in the background, allowing it to keep running even when the SSH connection is closed.
    DO NOT pass a string into commands!
    """
    # Make sure we source the environment variables placed in .profile first
    commands.insert(0, "source .profile")
    # Join commands with "&&" so we can use "cd" correctly
    separator = " && "
    # Use tmux to run the last command and detach it
    commands[-1] = f"tmux new -d {commands[-1]}"
    combined_commands = separator.join(commands)
    ssh.exec_command(combined_commands, get_pty=True)
    return

def subprocess_execute(commands: List[str], silent=False) -> bool:
    """
    Execute a list of commands in a subprocess.
    DO NOT pass a string into commands!
    """
    separator = " && "
    combined_commands = separator.join(commands)
    process = subprocess.Popen(combined_commands, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not silent:
        for line in process.stdout:
            print(line)
    # Necessary for returncode to not be None
    process.wait()
    if process.returncode != 0:
        print(f"Error executing subprocess commands: {combined_commands}")
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