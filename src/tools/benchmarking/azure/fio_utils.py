import json
import csv
import os
import paramiko

def is_fio_installed(ssh):
    """
    Checks if fio is installed on the remote machine.
    """
    stdin, stdout, stderr = ssh.exec_command('which fio')
    fio_path = stdout.read().decode().strip()
    return fio_path != ''

def install_fio(ssh):
    """
    Installs fio on the remote machine.
    """
    install_fio_commands = [
        "sudo apt-get update",
        "sudo apt-get install -y fio"
    ]
    for cmd in install_fio_commands:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            print(f"Error executing command: {cmd}")
            print(stderr.read().decode())
            return False
    return True

def save_to_csv(job_name, result, output_file):
    # Extract relevant performance data from fio output
    jobs = result.get("jobs", [])
    if not jobs:
        print(f"No jobs found in fio output")
        return
    
    with open(output_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        for job in jobs:
            row = [
                job_name,
                job["jobname"],
                job["read"]["iops"],
                job["read"]["bw"],
                job["read"]["lat_ns"]["mean"],
                job["write"]["iops"],
                job["write"]["bw"],
                job["write"]["lat_ns"]["mean"]
            ]
            writer.writerow(row)

def run_multiple_fio_benchmarks(public_ip, username, private_key_path, vm_name, parameters_list, is_rollbaccine):
    """
    Execute multiple FIO benchmarks on the VM and retrieve the results.
    """
    try:
        import paramiko
        import os
        import json
        import csv

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(public_ip, username=username, key_filename=private_key_path)
        sftp = ssh.open_sftp()

        for parameters in parameters_list:
            job_name = parameters['name']
            if not is_rollbaccine:
                job_name = "normal_disk_" + job_name
            write_mode = parameters['write_mode']
            bs = parameters['bs']
            size = parameters.get('size', '')
            direct = parameters.get('direct', 1)
            runtime = parameters.get('runtime', 0)
            ramp_time = parameters.get('ramp_time', 0)
            filename = parameters.get('filename', '/tmp/fio_test_file')
            filename_format = parameters.get('filename_format', '')
            iodepth = parameters.get('iodepth', 1)
            numjobs = parameters.get('numjobs', 1)
            group_reporting = parameters.get('group_reporting', False)

            output_file = f'/home/{username}/{job_name}_fio_results.json'

            # Create the directory for the files if necessary
            file_dir = os.path.dirname(filename)
            if file_dir and file_dir != '/':
                mkdir_command = f'mkdir -p {file_dir}'
                print(f"Creating directory {file_dir} on {vm_name}")
                ssh.exec_command(mkdir_command)

            # Build the FIO command
            fio_command = (
                f'sudo fio '
                f'--name={job_name} '
                f'--rw={write_mode} '
                f'--direct={direct} '
                f'--bs={bs} '
            )

            if size:
                fio_command += f'--size={size} '
            if runtime > 0:
                fio_command += f'--runtime={runtime} '
                fio_command += f'--time_based '
            if ramp_time > 0:
                fio_command += f'--ramp_time={ramp_time} '
            fio_command += f'--filename={filename} '
            if filename_format:
                fio_command += f'--filename_format={filename_format} '
            fio_command += f'--output-format=json '
            fio_command += f'--iodepth={iodepth} '
            fio_command += f'--numjobs={numjobs} '
            if group_reporting:
                fio_command += '--group_reporting '

            # Include additional FIO options if provided
            additional_fio_options = parameters.get('additional_fio_options')
            if additional_fio_options:
                fio_command += f'{additional_fio_options} '

            fio_command += f'> {output_file}'

            print(f"Running FIO benchmark '{job_name}' on {vm_name}")
            print(f"FIO command: {fio_command}")

            # Execute the FIO command on the remote VM
            stdin, stdout, stderr = ssh.exec_command(fio_command)

            # Wait for the command to complete
            exit_status = stdout.channel.recv_exit_status()
            stdout_output = stdout.read().decode()
            stderr_output = stderr.read().decode()

            if exit_status == 0:
                print(f"FIO benchmark '{job_name}' completed successfully on {public_ip}")
                if stdout_output:
                    print(stdout_output)
            else:
                print(f"FIO benchmark '{job_name}' failed on {public_ip}")
                if stderr_output:
                    print(f"Error Output:\n{stderr_output}")
                continue  # Proceed to the next benchmark

            local_result_dir = './results'
            os.makedirs(local_result_dir, exist_ok=True)
            local_result_path = os.path.join(local_result_dir, f'{job_name}_fio_results.json')
            print(f"Retrieving FIO results for '{job_name}' from {public_ip} to {local_result_path}")
            try:
                sftp.get(output_file, local_result_path)
                print(f"FIO results for '{job_name}' saved to {local_result_path}")
                with open(local_result_path, 'r') as f:
                    fio_result = json.load(f)
                csv_output_file = os.path.join(local_result_dir, f'{job_name}_fio_results.csv')
                if not os.path.exists(csv_output_file):
                    with open(csv_output_file, mode='w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow([
                            "Job Name", "FIO Job", "Read IOPS", "Read Bandwidth (KB/s)",
                            "Read Latency (ns)", "Write IOPS", "Write Bandwidth (KB/s)",
                            "Write Latency (ns)"
                        ])
                save_to_csv(job_name, fio_result, csv_output_file)
                print(f"Results for '{job_name}' saved to {csv_output_file}")
            except Exception as e:
                print(f"Error retrieving FIO results for '{job_name}' from {public_ip}: {e}")
                continue  # Proceed to the next benchmark
    except Exception as e:
        print(f"Error running FIO benchmarks on {public_ip}: {e}")
        return False
    finally:
        if 'sftp' in locals():
            sftp.close()
        ssh.close()
    return True  # Indicate success