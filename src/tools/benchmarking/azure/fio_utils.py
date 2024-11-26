import os
import subprocess
import uuid
import itertools

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

def run_multiple_fio_benchmarks(fio_parameters_list, numjobs_list, is_rollbaccine, output_dir):
    """
    Executes FIO benchmarks with varying numbers of threads locally and retrieves the results.
    """
    total_benchmarks = len(fio_parameters_list) * len(numjobs_list)
    current_benchmark = 0
    print(f"Running {total_benchmarks} FIO benchmarks locally")
    for fio_parameters_template in fio_parameters_list:
        for numjobs in numjobs_list:
            parameters = fio_parameters_template.copy()
            parameters['numjobs'] = numjobs
            short_uuid = str(uuid.uuid4())[:4]
            job_name = f"{parameters['name']}_threads_{numjobs}_{short_uuid}"
            if not is_rollbaccine:
                job_name = "normal_disk_" + job_name

            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f'{job_name}_fio_results.json')

            fio_command = build_fio_command(parameters, output_file)

            print(f"Running FIO benchmark '{job_name}'")
            print(f"FIO command: {fio_command}")

            # Execute the FIO command locally
            result = subprocess.run(fio_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if result.returncode == 0:
                print(f"FIO benchmark '{job_name}' completed successfully")
                if result.stdout:
                    print(result.stdout.decode())
            else:
                print(f"FIO benchmark '{job_name}' failed")
                if result.stderr:
                    print(f"Error Output:\n{result.stderr.decode()}")
                continue  # Proceed to the next benchmark

            current_benchmark += 1
            print(f"Completed {current_benchmark} of {total_benchmarks} benchmarks")

    return True  # Indicate success

def build_fio_command(parameters, output_file):
    """
    Builds the FIO command based on the given parameters.
    """
    fio_command = (
        f'sudo fio '
        f'--name={parameters["name"]} '
        f'--rw={parameters["write_mode"]} '
        f'--direct={parameters.get("direct", 1)} '
        f'--bs={parameters["bs"]} '
    )
    if parameters.get('runtime', 0) > 0:
        fio_command += f'--runtime={parameters["runtime"]} '
        fio_command += '--time_based '
    if parameters.get('ramp_time', 0) > 0:
        fio_command += f'--ramp_time={parameters["ramp_time"]} '
    fio_command += f'--filename={parameters.get("filename", "/tmp/fio_test_file")} '
    if parameters.get('filename_format'):
        fio_command += f'--filename_format={parameters["filename_format"]} '
    fio_command += f'--output-format=json '
    fio_command += f'--iodepth={parameters.get("iodepth", 1)} '
    fio_command += f'--numjobs={parameters["numjobs"]} '
    if parameters.get('group_reporting', True):
        fio_command += '--group_reporting '
    if parameters.get('fsync', 0) == 1:
        fio_command += '--fsync=1 '

    # Include additional FIO options if provided
    additional_fio_options = parameters.get('additional_fio_options')
    if additional_fio_options:
        fio_command += f'{additional_fio_options} '

    fio_command += f'> {output_file}'
    print(f"fio_command: {fio_command}")
    return fio_command

# Possible values for each parameter
io_directions = ['read', 'write']
sequentialities = ['seq', 'rand']
bufferings = [1, 0]  # direct=1 (Direct I/O) or direct=0 (Buffered I/O)
persistences = [1, 0]  # fsync=1 (Synchronous) or fsync=0 (Asynchronous)

# Generate all permutations
all_combinations = list(itertools.product(io_directions, sequentialities, bufferings, persistences))
all_combinations = [combo for combo in all_combinations if not (combo[0] == 'read' and combo[3] == 1)]
fio_parameters_list = []
print(f"all_combinations: {all_combinations}")

for io_direction, sequentiality, direct_io, fsync in all_combinations:
    # Construct the 'rw' parameter for FIO
    if sequentiality == 'seq':
        rw = io_direction
    else:
        rw = 'rand' + io_direction

    # Build the fio parameter dictionary
    fio_param = {
        'name': f'{sequentiality}_{io_direction}_direct{direct_io}_fsync{fsync}',
        'write_mode': rw,
        'bs': '4k',
        'direct': direct_io,
        'filename': '/dev/sdb1',
        'runtime': 30,
        'ramp_time': 60,
        'group_reporting': True,
    }

    # Add fsync parameter if persistence is required
    if fsync == 1:
        fio_param['fsync'] = 1  # Issue fsync after each write

    fio_parameters_list.append(fio_param)

# Define the list of numjobs (thread counts) you want to test
numjobs_list = [1, 2, 4, 8, 16]

#print(f"fio_parameters_list: {fio_parameters_list}")

if __name__ == "__main__":
    run_multiple_fio_benchmarks(fio_parameters_list, numjobs_list, True, 'results')