import os
import uuid
import itertools
import sys
import time

# Add the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from benchmark import *
from utils import *

class FioBenchmark(Benchmark):
    def build_fio_command(self, parameters, output_file):
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

        fio_command += f'| tee {output_file}'
        return fio_command
    
    def build_fio_parameters_list(self, system_type: System):
        filename = mount_point(system_type)

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
                'filename': filename,
                'runtime': 30,
                'ramp_time': 60,
                'group_reporting': True,
            }

            # Add fsync parameter if persistence is required
            if fsync == 1:
                fio_param['fsync'] = 1  # Issue fsync after each write

            fio_parameters_list.append(fio_param)
        return fio_parameters_list
    def filename(self):
        return "fio/fio_utils.py"
    
    def num_vms(self):
        return 1
    
    def benchmarking_vm(self):
        return 0 # Run fio on the primary
    
    def needs_storage(self) -> bool:
        return False

    def install(self, connections: List[SSHClient], private_ips: List[str], system_type: System, storage_name: str, storage_key: str):
        ssh = connections[self.benchmarking_vm()]
        if not is_installed(ssh, 'which fio'):
            return ssh_execute(ssh, [
                "sudo apt-get update -qq",
                "sudo apt-get install -y -qq fio"
            ])
        return True

    def run(self, system_type: System, output_dir: str):
        # Define the list of numjobs (thread counts) to test
        numjobs_list = [1, 2, 4, 8, 16]
        fio_parameters_list = self.build_fio_parameters_list(system_type)
        total_benchmarks = len(fio_parameters_list) * len(numjobs_list)
        current_benchmark = 0
        print(f"Running {total_benchmarks} FIO benchmarks locally")

        success = subprocess_execute([f"sudo umount {MOUNT_DIR}"])
        if not success:
            print("Failed to unmount the mount point")
            return

        for fio_parameters_template in fio_parameters_list:
            for numjobs in numjobs_list:
                parameters = fio_parameters_template.copy()
                parameters['numjobs'] = numjobs
                short_uuid = str(uuid.uuid4())[:4]
                job_name = f"{system_type}_{parameters['name']}_threads_{numjobs}_{short_uuid}"

                output_file = os.path.join(output_dir, f'{job_name}_fio_results.json')

                fio_command = self.build_fio_command(parameters, output_file)

                print(f"Running FIO benchmark '{job_name}'")
                print(f"FIO command: {fio_command}")

                start_time = time.time()
                # Execute the FIO command locally
                success = subprocess_execute([fio_command])
                if success:
                    print(f"FIO benchmark '{job_name}' completed successfully")
                else:
                    print(f"FIO benchmark '{job_name}' failed")
                    sys.exit(1)
                    return

                current_benchmark += 1
                end_time = time.time()
                print(f"***Elapsed time: {end_time - start_time:.2f} seconds, estimated remaining time: {(total_benchmarks - current_benchmark) * (end_time - start_time) / 60:.2f} minutes, completed {current_benchmark} of {total_benchmarks} benchmarks***")

if __name__ == "__main__":
    FioBenchmark().run(System[sys.argv[1]], sys.argv[2])