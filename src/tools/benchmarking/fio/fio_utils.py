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
    def get_fio_commands(self, system_type: System):
        if system_type == System.UNREPLICATED:
            return [
                # Rand read, buffered
                ('read', 'rand', 0, 0, 1),
                ('read', 'rand', 0, 0, 4),
                ('read', 'rand', 0, 0, 8),
                ('read', 'rand', 0, 0, 16),
                ('read', 'rand', 0, 0, 32),
                # Rand read, direct
                ('read', 'rand', 1, 0, 1),
                ('read', 'rand', 1, 0, 4),
                ('read', 'rand', 1, 0, 8),
                ('read', 'rand', 1, 0, 16),
                ('read', 'rand', 1, 0, 32),
                # Read, buffered
                ('read', '', 0, 0, 1),
                ('read', '', 0, 0, 4),
                ('read', '', 0, 0, 6),
                # Read, direct
                ('read', '', 1, 0, 1),
                ('read', '', 1, 0, 4),
                ('read', '', 1, 0, 8),
                ('read', '', 1, 0, 16),
                ('read', '', 1, 0, 32),
                # Rand write, buffered
                ('write', 'rand', 0, 0, 1),
                ('write', 'rand', 0, 0, 4),
                # Rand write, direct
                ('write', 'rand', 1, 0, 1),
                ('write', 'rand', 1, 0, 4),
                ('write', 'rand', 1, 0, 8),
                ('write', 'rand', 1, 0, 16),
                ('write', 'rand', 1, 0, 32),
                # Write, buffered
                ('write', '', 0, 0, 1),
                ('write', '', 0, 0, 4),
                ('write', '', 0, 0, 8),
                ('write', '', 0, 0, 16),
                ('write', '', 0, 0, 32),
                ('write', '', 0, 0, 64),
                ('write', '', 0, 0, 128),
                # Write, direct
                ('write', '', 1, 0, 1),
                ('write', '', 1, 0, 4),
                ('write', '', 1, 0, 8),
                ('write', '', 1, 0, 16),
                ('write', '', 1, 0, 32),
                # Rand write, fsync, buffered
                ('write', 'rand', 0, 1, 1),
                ('write', 'rand', 0, 1, 4),
                ('write', 'rand', 0, 1, 8),
                ('write', 'rand', 0, 1, 16),
                ('write', 'rand', 0, 1, 32),
                # Rand write, fsync, direct
                ('write', 'rand', 1, 1, 1),
                ('write', 'rand', 1, 1, 4),
                ('write', 'rand', 1, 1, 8),
                ('write', 'rand', 1, 1, 16),
                ('write', 'rand', 1, 1, 32),
                # Write, fsync, buffered
                ('write', '', 0, 1, 1),
                ('write', '', 0, 1, 4),
                ('write', '', 0, 1, 8),
                ('write', '', 0, 1, 16),
                # Write, fsync, direct
                ('write', '', 1, 1, 1),
                ('write', '', 1, 1, 4),
                ('write', '', 1, 1, 8),
                ('write', '', 1, 1, 16),
                ('write', '', 1, 1, 32),
            ]
        elif system_type == System.REPLICATED:
            return [
                # Rand read, buffered
                # ('read', 'rand', 0, 0, 1),
                # ('read', 'rand', 0, 0, 4),
                # ('read', 'rand', 0, 0, 8),
                # ('read', 'rand', 0, 0, 16),
                # ('read', 'rand', 0, 0, 32),
                # ('read', 'rand', 0, 0, 64),
                # Rand read, direct
                # ('read', 'rand', 1, 0, 1),
                # ('read', 'rand', 1, 0, 4),
                # ('read', 'rand', 1, 0, 8),
                # ('read', 'rand', 1, 0, 16),
                # ('read', 'rand', 1, 0, 32),
                # ('read', 'rand', 1, 0, 64),
                # Read, buffered
                # ('read', '', 0, 0, 1),
                # ('read', '', 0, 0, 4),
                # ('read', '', 0, 0, 8),
                # Read, direct
                # ('read', '', 0, 0, 1),
                # ('read', '', 0, 0, 4),
                # ('read', '', 0, 0, 8),
                # ('read', '', 0, 0, 16),
                ('read', '', 0, 0, 32),
                ('read', '', 0, 0, 64),
                ('read', '', 0, 0, 128),
                ('read', '', 0, 0, 256),
                # Rand write, buffered
                # ('write', 'rand', 0, 0, 1),
                # ('write', 'rand', 0, 0, 4),
                # ('write', 'rand', 0, 0, 8),
                # Rand write, direct
                # ('write', 'rand', 1, 0, 1),
                # ('write', 'rand', 1, 0, 4),
                # ('write', 'rand', 1, 0, 8),
                # ('write', 'rand', 1, 0, 16),
                # ('write', 'rand', 1, 0, 32),
                # ('write', 'rand', 1, 0, 64),
                # Write, buffered
                # ('write', '', 0, 0, 1),
                # ('write', '', 0, 0, 4),
                # ('write', '', 0, 0, 8),
                # ('write', '', 0, 0, 16),
                # ('write', '', 0, 0, 32),
                # ('write', '', 0, 0, 64),
                ('write', '', 0, 0, 128),
                ('write', '', 0, 0, 256),
                # Write, direct
                # ('write', '', 1, 0, 1),
                # ('write', '', 1, 0, 4),
                # ('write', '', 1, 0, 8),
                # ('write', '', 1, 0, 16),
                # ('write', '', 1, 0, 32),
                ('write', '', 1, 0, 64),
                # Rand write, fsync, buffered
                # ('write', 'rand', 0, 1, 1),
                # ('write', 'rand', 0, 1, 4),
                # ('write', 'rand', 0, 1, 8),
                # ('write', 'rand', 0, 1, 16),
                # ('write', 'rand', 0, 1, 32),
                ('write', 'rand', 0, 1, 64),
                # Rand write, fsync, direct
                # ('write', 'rand', 1, 1, 1),
                # ('write', 'rand', 1, 1, 4),
                # ('write', 'rand', 1, 1, 8),
                # ('write', 'rand', 1, 1, 16),
                # ('write', 'rand', 1, 1, 32),
                # ('write', 'rand', 1, 1, 64),
                # Write, fsync, buffered
                # ('write', '', 0, 1, 1),
                # ('write', '', 0, 1, 4),
                # ('write', '', 0, 1, 8),
                # ('write', '', 0, 1, 16),
                ('write', '', 0, 1, 32),
                ('write', '', 0, 1, 64),
                # Write, fsync, direct
                # ('write', '', 1, 1, 1),
                # ('write', '', 1, 1, 4),
                # ('write', '', 1, 1, 8),
                # ('write', '', 1, 1, 16),
                # ('write', '', 1, 1, 32),
                # ('write', '', 1, 1, 64),
            ]
        elif system_type == System.DM:
            return [
                # Rand read, buffered
                ('read', 'rand', 0, 0, 1),
                ('read', 'rand', 0, 0, 4),
                ('read', 'rand', 0, 0, 8),
                ('read', 'rand', 0, 0, 16),
                ('read', 'rand', 0, 0, 32),
                # Rand read, direct
                ('read', 'rand', 1, 0, 1),
                ('read', 'rand', 1, 0, 4),
                ('read', 'rand', 1, 0, 8),
                ('read', 'rand', 1, 0, 16),
                ('read', 'rand', 1, 0, 32),
                # Read, buffered
                ('read', '', 0, 0, 1),
                ('read', '', 0, 0, 4),
                ('read', '', 0, 0, 6),
                # Read, direct
                ('read', '', 1, 0, 1),
                ('read', '', 1, 0, 4),
                ('read', '', 1, 0, 8),
                ('read', '', 1, 0, 16),
                ('read', '', 1, 0, 32),
                ('read', '', 1, 0, 64),
                # Rand write, buffered
                ('write', 'rand', 0, 0, 1),
                ('write', 'rand', 0, 0, 4),
                # Rand write, direct
                ('write', 'rand', 1, 0, 1),
                ('write', 'rand', 1, 0, 4),
                # Write, buffered
                ('write', '', 0, 0, 1),
                ('write', '', 0, 0, 4),
                ('write', '', 0, 0, 8),
                ('write', '', 0, 0, 16),
                ('write', '', 0, 0, 32),
                ('write', '', 0, 0, 64),
                # Write, direct
                ('write', '', 1, 0, 1),
                ('write', '', 1, 0, 4),
                # Rand write, fsync, buffered
                ('write', 'rand', 0, 1, 1),
                ('write', 'rand', 0, 1, 4),
                # Rand write, fsync, direct
                ('write', 'rand', 1, 1, 1),
                ('write', 'rand', 1, 1, 4),
                # Write, fsync, buffered
                ('write', '', 0, 1, 1),
                ('write', '', 0, 1, 4),
                ('write', '', 0, 1, 8),
                ('write', '', 0, 1, 16),
                ('write', '', 0, 1, 32),
                ('write', '', 0, 1, 64),
                ('write', '', 0, 1, 128),
                ('write', '', 0, 1, 256),
                ('write', '', 0, 1, 512),
                ('write', '', 0, 1, 1024),
                ('write', '', 0, 1, 2048),
                # Write, fsync, direct
                ('write', '', 1, 1, 1),
                ('write', '', 1, 1, 4),
                ('write', '', 1, 1, 8),
                ('write', '', 1, 1, 16),
                ('write', '', 1, 1, 32),
                ('write', '', 1, 1, 64),
                ('write', '', 1, 1, 128),
                ('write', '', 1, 1, 256),
                ('write', '', 1, 1, 512),
                ('write', '', 1, 1, 1024),
            ]
        elif system_type == System.ROLLBACCINE:
            return [
                # Rand read, buffered
                ('read', 'rand', 0, 0, 1),
                ('read', 'rand', 0, 0, 4),
                ('read', 'rand', 0, 0, 8),
                ('read', 'rand', 0, 0, 16),
                ('read', 'rand', 0, 0, 32),
                ('read', 'rand', 0, 0, 64),
                # Rand read, direct
                ('read', 'rand', 1, 0, 1),
                ('read', 'rand', 1, 0, 4),
                ('read', 'rand', 1, 0, 8),
                ('read', 'rand', 1, 0, 16),
                ('read', 'rand', 1, 0, 32),
                ('read', 'rand', 1, 0, 64),
                # Read, buffered
                ('read', '', 0, 0, 1),
                ('read', '', 0, 0, 4),
                ('read', '', 0, 0, 6),
                # Read, direct
                ('read', '', 1, 0, 1),
                ('read', '', 1, 0, 4),
                ('read', '', 1, 0, 8),
                ('read', '', 1, 0, 16),
                ('read', '', 1, 0, 32),
                ('read', '', 1, 0, 64),
                # Rand write, buffered
                ('write', 'rand', 0, 0, 1),
                ('write', 'rand', 0, 0, 4),
                # Rand write, direct
                ('write', 'rand', 1, 0, 1),
                ('write', 'rand', 1, 0, 4),
                ('write', 'rand', 1, 0, 8),
                ('write', 'rand', 1, 0, 16),
                ('write', 'rand', 1, 0, 32),
                ('write', 'rand', 1, 0, 64),
                # Write, buffered
                ('write', '', 0, 0, 1),
                ('write', '', 0, 0, 4),
                ('write', '', 0, 0, 8),
                ('write', '', 0, 0, 16),
                ('write', '', 0, 0, 32),
                ('write', '', 0, 0, 64),
                ('write', '', 0, 0, 128),
                ('write', '', 0, 0, 256),
                # Write, direct
                ('write', '', 1, 0, 1),
                ('write', '', 1, 0, 4),
                ('write', '', 1, 0, 8),
                ('write', '', 1, 0, 16),
                ('write', '', 1, 0, 32),
                ('write', '', 1, 0, 64),
                # Rand write, fsync, buffered
                ('write', 'rand', 0, 1, 1),
                ('write', 'rand', 0, 1, 4),
                ('write', 'rand', 0, 1, 8),
                ('write', 'rand', 0, 1, 16),
                ('write', 'rand', 0, 1, 32),
                ('write', 'rand', 0, 1, 64),
                # Rand write, fsync, direct
                ('write', 'rand', 1, 1, 1),
                ('write', 'rand', 1, 1, 4),
                ('write', 'rand', 1, 1, 8),
                ('write', 'rand', 1, 1, 16),
                ('write', 'rand', 1, 1, 32),
                ('write', 'rand', 1, 1, 64),
                ('write', 'rand', 1, 1, 128),
                ('write', 'rand', 1, 1, 256),
                # Write, fsync, buffered
                ('write', '', 0, 1, 1),
                ('write', '', 0, 1, 4),
                ('write', '', 0, 1, 8),
                ('write', '', 0, 1, 16),
                ('write', '', 0, 1, 32),
                ('write', '', 0, 1, 64),
                # Write, fsync, direct
                ('write', '', 1, 1, 1),
                ('write', '', 1, 1, 4),
                ('write', '', 1, 1, 8),
                ('write', '', 1, 1, 16),
                ('write', '', 1, 1, 32),
                ('write', '', 1, 1, 64),
                ('write', '', 1, 1, 64),
                ('write', '', 1, 1, 128),
                ('write', '', 1, 1, 256),
            ]
        else:
            print(f"Unknown system type: {system_type}")
            return []
        

    def build_fio_commands(self, system_type: System, mount_point: str, output_dir: str, extra_args: str, iteration: int):
        filename = mount_point
        all_combinations = self.get_fio_commands(system_type)
        fio_commands = []

        for io_direction, sequentiality, direct, fsync, num_jobs in all_combinations:
            rw = sequentiality + io_direction
            job_name = f"{system_type}_{rw}_direct{direct}_fsync{fsync}_threads_{num_jobs}_{extra_args}"
            output_file = os.path.join(output_dir, f'{job_name}_fio_results_{iteration}.json')

            fio_command = f'sudo fio --name={job_name} --rw={rw} --direct={direct} --filename={filename} --numjobs={num_jobs} --fsync={fsync} --bs=4k --ramp_time=30 --runtime=60 --time_based --output-format=json --iodepth=1 --group_reporting --end_fsync=1 | tee {output_file}'
            fio_commands.append(fio_command)
        return fio_commands
    
    def filename(self):
        return "fio/fio_utils.py"
    
    def num_vms(self):
        return 1
    
    def benchmarking_vm(self):
        return 0 # Run fio on the primary
    
    def needs_storage(self) -> bool:
        return False

    def install(self, ssh_executor: SSH, connections: List[SSHClient], private_ips: List[str], system_type: System, storage_name: str, storage_key: str):
        ssh = connections[self.benchmarking_vm()]
        if not is_installed(ssh, 'which fio'):
            return ssh_executor.exec(ssh, [
                "sudo apt-get update -qq",
                "sudo apt-get install -y -qq fio"
            ])
        return True

    def run(self, system_type: System, mount_point: str, output_dir: str, extra_args: str):
        success = subprocess_execute([f"sudo umount {MOUNT_DIR}"])
        if not success:
            print("Failed to unmount the mount point")
            return
        
        for i in range(0, NUM_REPETITIONS):
            print(f"Round {i}")

            fio_commands = self.build_fio_commands(system_type, mount_point, output_dir, extra_args, i)
            total_benchmarks = len(fio_commands)
            current_benchmark = 0
            print(f"Running {total_benchmarks} FIO benchmarks locally")

            for fio_command in fio_commands:
                print(f"Running FIO command: {fio_command}")

                start_time = time.time()
                # Execute the FIO command locally
                success = subprocess_execute([fio_command])
                if success:
                    print(f"FIO benchmark '{fio_command}' completed successfully")
                else:
                    print(f"FIO benchmark '{fio_command}' failed")
                    sys.exit(1)
                    return

                current_benchmark += 1
                end_time = time.time()
                print(f"***Elapsed time: {end_time - start_time:.2f} seconds, estimated remaining time: {(total_benchmarks - current_benchmark) * (end_time - start_time) / 60:.2f} minutes, completed {current_benchmark} of {total_benchmarks} benchmarks***")

if __name__ == "__main__":
    FioBenchmark().run(System[sys.argv[1]], sys.argv[2], sys.argv[3], sys.argv[4])