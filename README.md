# Rollbaccine
A Linux device mapper that uses replication to detect and recover from rollback attacks in VM-based TEEs.  
Rollbaccine will:
1. Encrypt and decrypt all sectors.
2. Check integrity on all sectors, forcing recovery on failure.
3. Replicate all writes to backups and wait for an ACK before returning from a `REQ_FUA` or `REQ_PREFLUSH`.


## Evaluation

Set up your Azure account by following instructions [here](#running-on-azure). You will have to modify `launch.sh` to use your own Azure subscription ID, which must be able to launch Standard_DC16ads_v5 and Standard_DC16as_v5 machines in North Europe Zone 3.

Here is the full list of commands to evaluate each benchmark. Be mindful of your vCPU quota limits per region, which may affect whether you are able to launch the VMs necessary; the comments above each experiment indicate how many VMs are necessary. I suggest running at most 2 experiments concurrently, waiting before the VMs from the previous experiment are deallocated before beginning the next one. Each experiment should take under an hour, except for `fio` experiments, so be prepared to allocate a day or two.

```bash
# General tests, 1 VM per experiment except for postgres, which uses 2 VMs.
python3 src/tools/benchmarking/run_benchmarks.py --system_type UNREPLICATED --benchmark_name fio
python3 src/tools/benchmarking/run_benchmarks.py --system_type UNREPLICATED --benchmark_name filebench
python3 src/tools/benchmarking/run_benchmarks.py --system_type UNREPLICATED --benchmark_name postgres
python3 src/tools/benchmarking/run_benchmarks.py --system_type UNREPLICATED --benchmark_name hdfs
python3 src/tools/benchmarking/run_benchmarks.py --system_type DM --benchmark_name fio
python3 src/tools/benchmarking/run_benchmarks.py --system_type DM --benchmark_name filebench
python3 src/tools/benchmarking/run_benchmarks.py --system_type DM --benchmark_name postgres
python3 src/tools/benchmarking/run_benchmarks.py --system_type DM --benchmark_name hdfs
python3 src/tools/benchmarking/run_benchmarks.py --system_type REPLICATED --benchmark_name fio
python3 src/tools/benchmarking/run_benchmarks.py --system_type REPLICATED --benchmark_name filebench
python3 src/tools/benchmarking/run_benchmarks.py --system_type REPLICATED --benchmark_name postgres
python3 src/tools/benchmarking/run_benchmarks.py --system_type REPLICATED --benchmark_name hdfs
# Rollbaccine tests, 2 VMs per experiment, except for postgres, which uses 3 VMs.
python3 src/tools/benchmarking/run_benchmarks.py --system_type ROLLBACCINE --benchmark_name fio
python3 src/tools/benchmarking/run_benchmarks.py --system_type ROLLBACCINE --benchmark_name filebench
python3 src/tools/benchmarking/run_benchmarks.py --system_type ROLLBACCINE --benchmark_name postgres
python3 src/tools/benchmarking/run_benchmarks.py --system_type ROLLBACCINE --benchmark_name hdfs
python3 src/tools/benchmarking/run_benchmarks.py --system_type ROLLBACCINE --benchmark_name hdfs --rollbaccine_sync_mode sync
python3 src/tools/benchmarking/postgres/postgres_gcp.py # Rollbaccine postgres with backup on GCP
# Nimble tests. 4 VMs per experiment
python3 src/tools/benchmarking/run_benchmarks.py --system_type UNREPLICATED --benchmark_name nimble_hdfs --nimble_batch_size 1 --nimble_storage
python3 src/tools/benchmarking/run_benchmarks.py --system_type UNREPLICATED --benchmark_name nimble_hdfs --nimble_batch_size 100 --nimble_storage
python3 src/tools/benchmarking/run_benchmarks.py --system_type UNREPLICATED --benchmark_name nimble_hdfs --nimble_batch_size 1
python3 src/tools/benchmarking/run_benchmarks.py --system_type UNREPLICATED --benchmark_name nimble_hdfs --nimble_batch_size 100
# Rollbaccine parameter tests
# 2 VMs
python3 src/tools/benchmarking/run_benchmarks.py --system_type ROLLBACCINE --benchmark_name postgres --rollbaccine_f 0
# 4 VMs
python3 src/tools/benchmarking/run_benchmarks.py --system_type ROLLBACCINE --benchmark_name postgres --rollbaccine_f 2
# 3 VMs per experiment
python3 src/tools/benchmarking/run_benchmarks.py --system_type ROLLBACCINE --benchmark_name postgres --rollbaccine_sync_mode sync
python3 src/tools/benchmarking/run_benchmarks.py --system_type ROLLBACCINE --benchmark_name postgres --rollbaccine_num_hash_disk_pages 614400
python3 src/tools/benchmarking/run_benchmarks.py --system_type ROLLBACCINE --benchmark_name postgres --rollbaccine_num_hash_disk_pages 616774
# Recovery (postgres). 3 VMs per experiment
python3 src/tools/benchmarking/recovery/recovery_postgres.py True
python3 src/tools/benchmarking/recovery/recovery_postgres.py False
# Recovery (random). 2 VMs per experiment
python3 src/tools/benchmarking/recovery/recovery_random.py False 100
python3 src/tools/benchmarking/recovery/recovery_random.py False 300
python3 src/tools/benchmarking/recovery/recovery_random.py False 600
```

Each experiment, upon completion, will download files to `results`. Run the following command to generate the graphs:
```bash
cd src/tools/benchmarking/fio
python3 plot_fio_results.py
cd ../hdfs
python3 hdfs_benchmark_graph.py
cd ../postgres
python3 postgres_clients.py
cd ../filebench
python3 filebench_benchmark_graph.py
cd ../recovery
python3 recovery_benchmark_graph.py
```
Graphs will be generated in `graphs`.

## Development setup

- [Setup](#setup)
- [Everyday development](#everyday-development)
- [Running on Azure](#running-on-azure)

Create a Ubuntu 24.04 LTS VM locally in order to compile and install the kernel module. Containers will not suffice; [kernel modules cannot be installed on containers](https://stackoverflow.com/q/62455239/4028758).

Download a [Ubuntu 24.04 LTS image](https://ubuntu.com/download/server). I downloaded the server install image since I don't need the GUI.

**Note: Make sure you download the image that has the same architecture as your computer -- Installations for *Alternate Architectures* can be found on the same page**

### Mac Setup
<details Mac>
<summary>Mac Setup</summary>
<br>

#### Creating the VM with UTM
Install [UTM](https://mac.getutm.app/), and configure the VM:
- Open UTM, then click "+"
- Virtualize
- Linux
- Browse, find the ISO image you downloaded earlier
- Configure memory and CPU
- Configure disk size
- For the shared directory path, navigate to and select the directory of this repo (clone this repo if you haven't already).
- Give the VM a name and save.

Install Ubuntu:
- Start the VM
- Install Ubuntu Server
- Enter your preferred username and password
- Check Install OpenSSH Server
- Wait until the install finishes, then select "Reboot now"
- In UTM, select CD/DVD and clear (this simulates ejecting disk)
- Enter your username and password

Write down the IPv4 address of the VM. It should be under the "Welcome to Ubuntu" message in the VM.
Then execute `ssh user@ip` on your machine, where `user` is the username you chose and `ip` is the IP address of the VM. You're in!

Enable sharing directories with VirtFS on the VM:
```bash
sudo mkdir rollbaccine
sudo mount -t 9p -o trans=virtio share rollbaccine -oversion=9p2000.L
sudo chown -R $USER rollbaccine
```
Now this repo should be visible from within the VM! Automatically mount this directory on startup with:
```bash
echo "share	/home/$USER/rollbaccine	9p	trans=virtio,version=9p2000.L,rw,_netdev,nofail	0	0" | sudo tee -a /etc/fstab
```

For convenience SSHing into the VM, add the following to your machine's `~/.ssh/config`:
```bash
Host localvm
  HostName <ip>
  User <username>
```
Replacing the IP address and username with your VM's.

Outside the VM, run the following so we don't need to re-enter the password every time we SSH into the VM:
```bash
ssh-copy-id localvm
```
This command fails if you don't have ssh keys on your machine. Create those with `ssh-keygen`, using the defaults whenever prompted.
</details>

### Windows Setup
<details>
<summary>Windows Setup</summary>
<br>

Install [Oracle virtual box](https://www.virtualbox.org/wiki/Downloads) and configure the VM:

1. Create new machine and browse to find the ISO image you downloaded earlier
2. Create username and password
3. Check Guest Additions (allows for shared directories between host and VM)
4. Configure memory and CPU
5. Configure disk size
6. Give the VM name and save

Install Ubuntu:

1. Start the VM
2. The default options for setup are sufficient
3. Input the same username and password from earlier
4. Check Install OpenSSH Server
5. Wait for System to install

Enabling Sharing Directories

1. Select `Devices>Shared Folders>Shared Folder Settings`
2. Add a new folder and select this repo to share. Set mount point to `/home/<username>/rollbaccine` and check `Auto-Mount`, `Make Permanent` 
3. `sudo apt-get install virtualbox-guest-utils` 
4. `sudo usermod -aG vboxsf <your_username>` for access privilege’s
5. restart VM to see `rollbaccine` folder

Setting Up SSH

1. `sudo apt install net-tools`
2. Run `ifconfig -a` to find IP address next to `inet` on the top left of the output command and write it down
3. To open a port and allow the host machine to connect the VM run
```bash
sudo ufw allow ssh
sudo ufw status verbose
```

4. Go to `Devices>Network>Network Settings`, ensure `NAT` is selected and click on `Advanced`
5. Select `Port Forwarding` and add a new entry with `Name: ssh, Protocol: TCP, Host Port: 2222, Guest Port: 22`
6. Now entering `ssh -p 2222 virtualbox-user-name@localhost` on host machine will ssh into VM!
7. For convenience SSHing into the VM, add the following to your host machine's `~/.ssh/config`:

```bash
Host localvm
  HostName localhost
  Port 2222
  User <vm_username>
```
</details>


#### Setting up the VM
To avoid having to type your password on sudo, execute the following:
```bash
sudo passwd -d <vm_username>
```

Install the necessary packages:
```bash
sudo apt update
sudo apt install -y build-essential
```
[Install the GitHub CLI](https://github.com/cli/cli/blob/trunk/docs/install_linux.md#debian-ubuntu-linux-raspberry-pi-os-apt) so you can push changes after developing in the VM.


#### VSCode setup

To use VSCode in the VM, click the blue >< box in VSCode's bottom left corner, select "Connect to Host", and select "localvm". Install the necessary extensions (C++, Github copilot).

In order for VSCode to understand Linux kernel headers, we will follow instructions from the [vscode-linux-kernel](https://github.com/amezin/vscode-linux-kernel) repo:
```bash
cd rollbaccine
rm -rf .vscode
git clone https://github.com/amezin/vscode-linux-kernel .vscode
python3 .vscode/generate_compdb.py -O /lib/modules/$(uname -r)/build $PWD
```


#### Everyday development
After modifying the kernel module, compile `src/rollbaccine.c` with and install it with:
```bash
cd src
make
sudo modprobe brd rd_nr=2 rd_size=1048576
sudo insmod rollbaccine.ko
echo "0 `sudo blockdev --getsz /dev/ram0` rollbaccine /dev/ram0 1 1 true abcdefghijklmnop 1 0 default 12340 false false 2" | sudo dmsetup create rollbaccine1
echo "0 `sudo blockdev --getsz /dev/ram1` rollbaccine /dev/ram1 2 1 false abcdefghijklmnop 1 0 default 12350 false false 1 127.0.0.1 12340" | sudo dmsetup create rollbaccine2
```
Here's the syntax, explained:
- `dmsetup create rollbaccine1`: Create a device mapper and name it rollbaccine1.
- `echo ...`: A table (from stdin) of the form `logical_start_sector num_sectors target_type target_args`.
  - `logical_start_sector`: 0, the start of the device.
  - `num_sectors`: The number of sectors in the device. You can get the number of sectors of a device with `blockdev --getsz $1`, where `$1` is the device.
  - `target_type`: The name of the device mapper.
  - `target_args`: Device to map onto.
The remaining parameters' purposes can be found in the `rollbaccine_constructor` method of `src/rollbaccine.c`.  

You can now write directly to `/dev/mapper/rollbaccine1`! You can also mount a file system over that directory.

> [!TIP]  
> To view the outputs of your module, execute `sudo dmesg -w`. To see values printed by the `status()` function, execute `sudo dmsetup status rollbaccine1`, replacing `rollbaccine` with the name you gave the launched rollbaccine device.

Once we're done, unload the module and uninstall the module with:
```bash
sudo dmsetup remove rollbaccine2
sudo dmsetup remove rollbaccine1
sudo rmmod rollbaccine
```

If you ever need to clear the ramdisks, run:
```bash
sudo modprobe -r brd
```

#### Testing writes/reads to block device
We use `fio` to benchmark performance. However, `fio` is not ideal for testing to see if a block device works, because it spins up multiple threads that spam a block device with writes and reads. To see if a block device can handle small individual reads and writes, use [device_tester.c](src/tools/device_tester.c).

Compile the device tester:
```bash
cd tools
make
```

Set up the block devices as described in [Everyday development](#everyday-development). Then run the device tester over it:
```bash
sudo ./device_tester /dev/mapper/rollbaccine1 write
sudo ./device_tester /dev/mapper/rollbaccine1 read
```

For those who are curious, none of the other folders in `src` are used in `rollbaccine.c`. They are minimal experiments we used during development in order to understand how to write a device mapper.


## Running on Azure

If you haven't already, [install the Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) and log in:
```bash
az login
```

Create a Python venv and install the dependencies:
```bash
python -m venv .
source bin/activate
pip install -r src/tools/benchmarking/requirements.txt
```
If your keys in `~/.ssh/id_rsa` are password-protected, create password-less SSH keys (clicking Enter on all options):
```bash
cd ~/.ssh
ssh-keygen -t rsa -b 4096
```

Note that each time you restart the terminal, you will need to reactivate the venv with `source bin/activate`.

### Launching VMs and cleaning up

To launch VMs, see [Evaluation](#evaluation). Results will be saved to `results/`.

If the script does not complete successfully, you will have to manually clean up resources when you are done debugging. To do so, run the following command:
```bash
./cleanup.h -s <system type> -b <benchmark name> -e <extra args>
```
The parameters for `<system type>`, `<benchmark name>`, and `<extra args>` can be found in the beginning of the output of the launch command.

### Testing against ACE

We verify that the backup contains disk that can be used to recover consistently with [ACE](https://github.com/utsaslab/crashmonkey/blob/master/docs/Ace.md).
We execute tests generated by ACE with [xfstests](https://github.com/kdave/xfstests), running them over the primary, and checking that the backup has the same state.
To run the tests yourself, run the following command:

```bash
python3 src/tools/benchmarking/ace/ace.py
```

## Running on GCP

Google Cloud is used for the multi-cloud experiment, where the VM on Google Cloud is used as the Rollbaccine backup.
The experiment can be found in [postgres_gcp.py](src/tools/benchmarking/postgres/postgres_gcp.py).

If you haven't already, [install the gcloud CLI](https://cloud.google.com/sdk/docs/install) and log in:
```bash
gcloud auth login
```

You will need to [enable the Compute Engine API](https://console.cloud.google.com/apis/library) to allow the creation of VM instances, networks, and firewall rules.

The script for launching VMs is [launch_gcp.sh](launch_gcp.sh). Do not run it individually, as it requires knowing the IP address of the Azure VM running Rollbaccine primary.
If the script does not complete successfully, you can manually clean up by running:
```bash
./cleanup_gcp.sh
```