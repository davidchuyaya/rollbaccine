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
    def discard_fio_command(self, system_type, io_direction, sequentiality, direct, fsync, num_jobs):
        """
        Returns which fio commands should be discarded based on the system config, in order to saturate individual configs (or stop after we've saturated)
        """
        if system_type == System.REPLICATED:
            return False
        if system_type == System.DM:
            if io_direction == 'write':
                if sequentiality == 'rand':
                    if direct == 0:
                        if fsync == 1:
                            if num_jobs > 8:
                                return True
                    else: # direct = 1
                        if num_jobs > 4:
                            return True
                else: # sequential
                    if direct == 1 and fsync == 0:
                        if num_jobs > 4:
                            return True
        if sequentiality == 'rand' and io_direction == 'write' and direct == 0 and fsync == 0 and num_jobs > 4:
            return True
        if sequentiality == '' and io_direction == 'read' and direct == 0 and fsync == 0 and num_jobs > 6:
            return True
        return False

    def build_fio_commands(self, system_type: System, output_dir: str):
        filename = mount_point(system_type)

        # Possible values for each parameter. Most intense options first so we see errors early
        io_directions = ['write', 'read']
        sequentialities = ['', 'rand'] # Empty string means sequential
        bufferings = [0, 1]  # direct=1 (Direct I/O) or direct=0 (Buffered I/O)
        persistences = [0, 1]  # writefua=1 (Synchronous) or writefua=0 (Asynchronous)
        num_jobs_list = [32, 16, 8, 4, 1]

        # Replicated disk saturates very quickly, don't run too many jobs
        if system_type == System.REPLICATED:
            num_jobs_list = [16, 8, 1]

        # Generate all permutations
        all_combinations = list(itertools.product(io_directions, sequentialities, bufferings, persistences, num_jobs_list))
        all_combinations = [combo for combo in all_combinations if not (combo[0] == 'read' and combo[3] == 1)]

        fio_commands = []
        # Add additional commands
        if system_type == System.DM:
            # DM sequential writes with fsync do very well, add more
            all_combinations.insert(0, ('write', '', 0, 1, 256))
            all_combinations.insert(0, ('write', '', 0, 1, 1024))
            all_combinations.insert(0, ('write', '', 0, 1, 2048))
            all_combinations.insert(0, ('write', '', 1, 1, 256))
            all_combinations.insert(0, ('write', '', 1, 1, 1024))
        if system_type == System.ROLLBACCINE:
            all_combinations.insert(0, ('write', '', 0, 0, 256))
            all_combinations.insert(0, ('write', '', 0, 1, 1024))
            all_combinations.insert(0, ('write', '', 1, 1, 256))
            all_combinations.insert(0, ('write', '', 1, 1, 1024))
            all_combinations.insert(0, ('write', 'rand', 0, 1, 128))
            all_combinations.insert(0, ('write', 'rand', 1, 1, 256))
            all_combinations.insert(0, ('write', 'rand', 1, 1, 1024))
            all_combinations.insert(0, ('read', '', 1, 0, 64))
            all_combinations.insert(0, ('read', 'rand', 0, 0, 64))
            all_combinations.insert(0, ('read', 'rand', 1, 0, 64))
        all_combinations.insert(0, ('read', '', 0, 0, 6))
        all_combinations.insert(0, ('write', '', 0, 0, 64))
        all_combinations.insert(0, ('write', '', 0, 0, 128))

        for io_direction, sequentiality, direct, fsync, num_jobs in all_combinations:
            # Don't execute certain commands
            if self.discard_fio_command(system_type, io_direction, sequentiality, direct, fsync, num_jobs):
                continue

            rw = sequentiality + io_direction
            job_name = f"{system_type}_{rw}_direct{direct}_fsync{fsync}_threads_{num_jobs}_{str(uuid.uuid4())[:4]}"
            output_file = os.path.join(output_dir, f'{job_name}_fio_results.json')

            fio_command = f'sudo fio --name={job_name} --rw={rw} --direct={direct} --filename={filename} --numjobs={num_jobs} --writefua={fsync} --bs=4k --ramp_time=30 --runtime=60 --time_based --output-format=json --iodepth=1 --group_reporting --end_fsync=1 | tee {output_file}'
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

    def run(self, system_type: System, output_dir: str):
        success = subprocess_execute([f"sudo umount {MOUNT_DIR}"])
        if not success:
            print("Failed to unmount the mount point")
            return
        
        fio_commands = self.build_fio_commands(system_type, output_dir)
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
    FioBenchmark().run(System[sys.argv[1]], sys.argv[2])