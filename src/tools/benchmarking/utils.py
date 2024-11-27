from paramiko import SSHClient
from typing import List
from benchmark import *
import subprocess

def is_installed(ssh: SSHClient, command: str) -> bool:
    """
    Returns whether the given command produces an output or not
    """
    stdin, stdout, stderr = ssh.exec_command(command)
    path = stdout.read().decode().strip()
    return path != ''

def ssh_execute(ssh: SSHClient, commands: List[str]) -> bool:
    # Join commands with ";" so we can use "cd" correctly
    separator = ";"
    combined_commands = separator.join(commands)
    stdin, stdout, stderr = ssh.exec_command(combined_commands)
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        print(f"Error executing command: {combined_commands}")
        print(stderr.read().decode())
        return False
    return True

def subprocess_execute(commands: List[str]) -> bool:
    separator = ";"
    combined_commands = separator.join(commands)
    result = subprocess.run(combined_commands, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode == 0:
        if result.stdout:
            print(result.stdout.decode())
        return True
    else:
        if result.stderr:
            print(f"Error Output:\n{result.stderr.decode()}")
        return False

def upload(ssh: SSHClient, local_path: str, remote_path: str):
    sftp = ssh.open_sftp()
    sftp.put(local_path, remote_path)
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
    return [
        f"sudo mkfs.{file_system} -F {mount_path}",
        f"sudo mkdir -p {new_dir}",
        f"sudo mount {mount_path} {new_dir}",
    ]

def mount_ext4_commands(mount_path: str, new_dir: str) -> List[str]:
    return mount_commands('ext4', mount_path, new_dir)

def mount_xfs_commands(mount_path: str, new_dir: str) -> List[str]:
    return mount_commands('xfs', mount_path, new_dir)