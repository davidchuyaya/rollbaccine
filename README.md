# Rollbaccine
A Linux device mapper that uses replication to prevent rollback attacks in VM-based TEEs.  
Rollbaccine will:
1. Encrypt and decrypt all sectors.
2. Check integrity on all sectors, forcing recovery on failure. The hashes are kept in memory.
3. Replicate all writes to backups and wait for an ACK before returning from a `REQ_FUA` or `REQ_PREFLUSH`.


## Evaluation

Set up your Azure account by following instructions [here](#running-on-azure). You will have to modify `launch.sh` to use your own Azure subscription ID, which must be able to launch Standard_DC16ads_v5 machines in North Europe Zone 3.

Here is the full list of commands to evaluate each benchmark. Be mindful of your quota limits per region, which may affect whether you are able to launch the VMs necessary. Most experiments only use 1-2 VMs; Nimble HDFS uses 5, each with 16 cores, so that's 80 vCPUs. I suggest running at most 2 experiments concurrently. Each experiment should take at most 2 hours, so be prepared to allocate a day or two.

```bash
python3 src/tools/benchmarking/run_benchmarks.py UNREPLICATED fio
python3 src/tools/benchmarking/run_benchmarks.py UNREPLICATED filebench
python3 src/tools/benchmarking/run_benchmarks.py UNREPLICATED postgres
python3 src/tools/benchmarking/run_benchmarks.py UNREPLICATED hdfs
python3 src/tools/benchmarking/run_benchmarks.py DM fio
python3 src/tools/benchmarking/run_benchmarks.py DM filebench
python3 src/tools/benchmarking/run_benchmarks.py DM postgres
python3 src/tools/benchmarking/run_benchmarks.py DM hdfs
python3 src/tools/benchmarking/run_benchmarks.py REPLICATED fio
python3 src/tools/benchmarking/run_benchmarks.py REPLICATED filebench
python3 src/tools/benchmarking/run_benchmarks.py REPLICATED postgres
python3 src/tools/benchmarking/run_benchmarks.py REPLICATED hdfs
python3 src/tools/benchmarking/run_benchmarks.py ROLLBACCINE fio
python3 src/tools/benchmarking/run_benchmarks.py ROLLBACCINE filebench
python3 src/tools/benchmarking/run_benchmarks.py ROLLBACCINE postgres
python3 src/tools/benchmarking/run_benchmarks.py ROLLBACCINE hdfs
python3 src/tools/benchmarking/recovery/recovery.py True
python3 src/tools/benchmarking/run_benchmarks.py UNREPLICATED nimble_hdfs 1
python3 src/tools/benchmarking/recovery/recovery.py False # Don't immediately run after the previous recovery, since the resource group names are the same, and shutting down a group takes time.
python3 src/tools/benchmarking/run_benchmarks.py UNREPLICATED nimble_hdfs 100
```

Each experiment, upon completion, will download files to the root directory (except for `recovery`, which directly puts the files in `results/recovery`). Move the files to the `results` folder under the right benchmark name (`nimble_hdfs` is put in `hdfs`), then run the following command to generate the graphs:
```bash
cd src/tools/benchmarking/fio
python3 plot_fio_results.py
cd ../hdfs
python3 hdfs_benchmark_graph.py
cd ../postgres
python3 postgres_benchmark_graph.py
cd ../filebench
python3 filebench_benchmark_graph.py
cd ../recovery
python3 recovery_benchmark_graph.py
```
Graphs will be generated in `results/graphs`.

## Development setup

- [Setup](#setup)
- [Everyday development](#everyday-development)
- [Benchmarking](#benchmarking)

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


#### VSCode setup

To use VSCode in the VM, click the blue >< box in VSCode's bottom left corner, select "Connect to Host", and select "localvm". Install the necessary extensions (C++, Github copilot).

In order for VSCode to understand Linux kernel headers, we will follow instructions from the [vscode-linux-kernel](https://github.com/amezin/vscode-linux-kernel) repo:
```bash
cd rollbaccine
rm -rf .vscode
git clone https://github.com/amezin/vscode-linux-kernel .vscode
python3 .vscode/generate_compdb.py -O /lib/modules/$(uname -r)/build $PWD
```


#### Setting up the VM
To avoid having to type your password on sudo, execute the following:
```bash
sudo passwd -d davidchu
```
Replace `davidchu` with your username.

Install the necessary packages:
```bash
sudo apt update
sudo apt install -y build-essential
```
[Install the GitHub CLI](https://github.com/cli/cli/blob/trunk/docs/install_linux.md#debian-ubuntu-linux-raspberry-pi-os-apt) so you can push changes after developing in the VM.


#### Everyday development
After modifying the kernel module, compile `src/rollbaccine.c` with and install it with:
```bash
cd src
make
sudo modprobe brd rd_nr=2 rd_size=1048576
sudo insmod rollbaccine.ko
echo "0 `sudo blockdev --getsz /dev/ram0` rollbaccine /dev/ram0 1 1 true abcdefghijklmnop 12340 2 127.0.0.1 12350" | sudo dmsetup create rollbaccine1
echo "0 `sudo blockdev --getsz /dev/ram1` rollbaccine /dev/ram1 2 1 false abcdefghijklmnop 12350 1 127.0.0.1 12340" | sudo dmsetup create rollbaccine2
```
Here's the syntax, explained:
- `dmsetup create rollbaccine1`: Create a device mapper and name it rollbaccine1.
- `echo ...`: A table (from stdin) of the form `logical_start_sector num_sectors target_type target_args`.
  - `logical_start_sector`: 0, the start of the device.
  - `num_sectors`: The number of sectors in the device. You can get the number of sectors of a device with `blockdev --getsz $1`, where `$1` is the device.
  - `target_type`: The name of the device mapper.
  - `target_args`: Device to map onto.
The remaining parameters' purposes can be found in `src/rollbaccine.c`.  
Briefly (this may become out-of-date), the parameters are: ID, seen_ballot, is_leader, password, listen_port, counterpart_id, counterpart_addr, counterpart_port. During reconfiguration, additional id, addr, port parameters are passed in.

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
We will use `fio` to benchmark performance, as seen in [Benchmarking](#benchmarking). However, `fio` is not ideal for testing to see if a block device works, because it will multiple threads that spam a block device with writes and reads. To see if a block device can handle small individual reads and writes, use [device_tester.c](src/tools/device_tester.c).

Compile the device tester:
```bash
cd tools
make
```

Set up the block devices as described in [Benchmarking](#benchmarking). Then run the device tester over it. Here we will run the device tester over ramdisk `/dev/ram0`:
```bash
sudo ./device_tester /dev/ram0 write
sudo ./device_tester /dev/ram0 read
```

For those who are curious, none of the other folders in `src` are used in `rollbaccine.c`. They are minimal experiments we used during development in order to understand how to write a device mapper.


## Running on Azure

If you haven't already, install the Azure CLI and log in:
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login
```

TODO: Include instructions for setting up venv  
Install Python dependencies:
```bash
pip install -r src/tools/benchmarking/requirements.txt
```
If your keys in `~/.ssh/id_rsa` are password-protected, create password-less SSH keys (clicking Enter on all options):
```bash
cd ~/.ssh
ssh-keygen -t rsa -b 4096
```

### Launching VMs and cleaning up

To launch VMs, run the following command **from the root of this directory**:
```bash
python3 src/tools/benchmarking/run_benchmarks.py <system type> <benchmark name>
```
`<system type>` is one of `UNREPLICATED`, `DM`, `REPLICATED`, or `ROLLBACCINE`.  
`<benchmark name>` is one of `fio`, `filebench`, `postgres`, `hdfs`, or `nimble_hdfs`.  
Outputs will be saved to the root of this directory.

If the script does not complete successfully, you will have to manually clean up resources when you are done debugging. To do so, run the following command:
```bash
./cleanup.h -s <system type> -b <benchmark name> 
```

### Testing against ACE

We verify that the backup contains disk that can be used to recover consistently with [ACE](https://github.com/utsaslab/crashmonkey/blob/master/docs/Ace.md).
We execute tests generated by ACE with [xfstests](https://github.com/kdave/xfstests), running them over the primary, and checking that the backup has the same state.
To run the tests yourself, run the following command:

```bash
python3 src/tools/benchmarking/ace/ace.py
```
