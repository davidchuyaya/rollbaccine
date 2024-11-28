from abc import ABC, abstractmethod
from enum import Enum
from typing import List
from paramiko import SSHClient

class System(Enum):
    UNREPLICATED = 1
    DM = 2
    REPLICATED = 3
    ROLLBACCINE = 4

    def __str__(self):
        return f'{self.name}'

class Benchmark(ABC):
    @abstractmethod
    def name(self) -> str:
        """
        Returns the print-friendly name of the benchmark.
        """
        pass

    @abstractmethod
    def filename(self) -> str:
        """
        Returns the filename of the benchmarking tool, from the src/tools/benchmarking directory.
        """
        pass

    @abstractmethod
    def num_vms(self) -> int:
        """
        Returns the number of VMs required to run the benchmark (in the unreplicated setting).
        """
        pass

    @abstractmethod
    def benchmarking_vm(self) -> int:
        """
        Returns the index of the VM that will run the benchmark.
        """
        pass

    @abstractmethod
    def needs_storage(self) -> bool:
        """
        Returns whether the benchmark requires Azure storage.
        """
        pass

    @abstractmethod
    def install(self, connections: List[SSHClient], private_ips: List[str], system_type: System, storage_name: str, storage_key: str) -> bool:
        """
        Installs the benchmarking tool on the remote machine if necessary.
        By convention, the first connection is the Rollbaccine primary, if any.
        This list will NOT contain the Rollbaccine backup, if any.
        """
        pass

    @abstractmethod
    def run(self, system_type: System, output_dir: str) -> bool:
        """
        Executes benchmarks locally and retrieves the results.
        """
        pass