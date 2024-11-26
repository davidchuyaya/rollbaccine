from paramiko import SSHClient
from typing import List

def is_installed(ssh: SSHClient, command: str) -> bool:
    stdin, stdout, stderr = ssh.exec_command(command)
    path = stdout.read().decode().strip()
    return path != ''

def ssh_execute(ssh: SSHClient, commands: List[str]) -> str:
    for cmd in commands:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            print(f"Error executing command: {cmd}")
            print(stderr.read().decode())
            return False
    return True

def upload(ssh: SSHClient, local_path: str, remote_path: str):
    sftp = ssh.open_sftp()
    sftp.put(local_path, remote_path)
    sftp.close()