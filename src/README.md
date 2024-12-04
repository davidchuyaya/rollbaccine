# Development setup

- [Setup](#setup)
- [Everyday development](#everyday-development)
- [Benchmarking](#benchmarking)

Create a Ubuntu 24.04 LTS VM locally in order to compile and install the kernel module. Containers will not suffice; [kernel modules cannot be installed on containers](https://stackoverflow.com/q/62455239/4028758).



Download a [Ubuntu 24.04 LTS image](https://ubuntu.com/download/server). I downloaded the server install image since I don't need the GUI.

**Note: Make sure you download the image that has the same architecture as your computer -- Installations for *Alternate Architectures* can be found on the same page**

## Mac Setup
<details Mac>
<summary>Mac Setup</summary>
<br>

### Creating the VM with UTM
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
echo "share	/home/davidchu/rollbaccine	9p	trans=virtio,version=9p2000.L,rw,_netdev,nofail	0	0" | sudo tee -a /etc/fstab
```
Replace `davidchu` with your username.

For convenience SSHing into the VM, add the following to your machine's `~/.ssh/config`:
```bash
Host localvm
  HostName 192.168.64.3
  User davidchu
```
Replacing the IP address and username with your VM's.

Outside the VM, run the following so we don't need to re-enter the password every time we SSH into the VM:
```bash
ssh-copy-id localvm
```
</details>

## Windows Setup
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


### VSCode setup

To use VSCode in the VM, click the blue >< box in VSCode's bottom left corner, select "Connect to Host", and select "localvm". Install the necessary extensions (C++, Github copilot).

In order for VSCode to understand Linux kernel headers, we will follow instructions from the [vscode-linux-kernel](https://github.com/amezin/vscode-linux-kernel) repo:
```bash
cd rollbaccine
rm -rf .vscode
git clone https://github.com/amezin/vscode-linux-kernel .vscode
python3 .vscode/generate_compdb.py -O /lib/modules/$(uname -r)/build $PWD
```


### Setting up the VM
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


## Everyday development
After modifying the kernel module, compile it with and install it with:
```bash
cd src
make
sudo insmod rollbaccine.ko
```

> [!TIP]  
> To view the outputs of your module, execute `sudo dmesg | tail -10`. To see the outputs continuously, execute `sudo dmesg -wH`. To see all loaded kernel modules, run `sudo lsmod`.


Now that the module is loaded, we have to create the device with `dmsetup`.
```bash
echo "0 `sudo blockdev --getsz /dev/sda3` rollbaccine /dev/sda3" | sudo dmsetup create rollbaccine 
```
Here's the syntax, explained:
- `dmsetup create rollbaccine`: Create a device mapper and name it rollbaccine.
- `echo ...`: A table (from stdin) of the form `logical_start_sector num_sectors target_type target_args`.
  - `logical_start_sector`: 0, the start of the device.
  - `num_sectors`: The number of sectors in the device. You can get the number of sectors of a device with `blockdev --getsz $1`, where `$1` is the device.
  - `target_type`: The name of the device mapper.
  - `target_args`: Device to map onto.

Once we're done, unload the module and uninstall the module with:
```bash
sudo dmsetup remove rollbaccine
sudo rmmod rollbaccine
```


## Benchmarking
We will benchmark everything using `fio` against direct writes to RAM.
We use RAM instead of actual disk becuase storage hardware is "noisy".
First, create a 4GB ramdisk for testing, as described [here](https://blog.cloudflare.com/speeding-up-linux-disk-encryption). We'll use the actual disk for testing [fsync](#fsync).
```bash
sudo modprobe brd rd_nr=1 rd_size=4194304
```
There should now be a device at `/dev/ram0`.

Now we will measure the throughput of having no device mapper using `fio`.
```bash
sudo apt install -y fio
sudo fio --filename=/dev/ram0 --readwrite=readwrite --bs=4k --direct=1 --loops=20 --name=plain
```

To remove the ramdisk, run:
```bash
sudo modprobe -r brd
```


### Passthrough
Load the passthrough device driver and measure its throughput.
```bash
cd src/passthrough
make
sudo insmod passthrough.ko
echo "0 `sudo blockdev --getsz /dev/ram0` passthrough /dev/ram0" | sudo dmsetup create passthrough
sudo fio --filename=/dev/mapper/passthrough --readwrite=readwrite --bs=4k --direct=1 --loops=20 --name=passthrough
```


### Encryption
Measure the throughput overhead of dm-crypt. If you already ran `dmsetup` over `/dev/ram0`, you'll need to remove it with `sudo dmsetup remove <name>`, where `<name>` is the name of the previous device mapper.
```bash
sudo cryptsetup luksFormat /dev/ram0
sudo cryptsetup open --perf-no_read_workqueue --perf-no_write_workqueue --type luks /dev/ram0 secure
sudo fio --filename=/dev/mapper/secure --readwrite=readwrite --bs=4k --direct=1 --loops=2 --name=secure
```

Measure the throughput of our custom encrypting device mapper.


Load our encryption device mapper:
```bash
echo "0 `sudo blockdev --getsz /dev/ram0` encryption /dev/ram0" | sudo dmsetup create encryption
```


### Networking
Measure the throughput overhead of networking.  
Replace `<is_leader>` with true if this node's writes should be replicated.  
TODO: Remove this feature once leader election is implemented.  
Replace `<f>` with a number, minimum 1.  
Replace `<n>` with the number of nodes in the system, minimum 2.  
Replace `<id>` with the id of the node, starting from 0.  
Replace `<listen port>`, `<server addr 1>`, and `<server port 1>` with the desired ports, where you can supply a variable number of server addresses and ports, depending on how many servers this node should connect to.
```bash
echo "0 `sudo blockdev --getsz /dev/ram0` server /dev/ram0 <f> <n> <id> <is_leader> <listen port> <server addr 1> <server port 1>" | sudo dmsetup create server
```

For example, set up networking locally between 2 ramdisks with 1GBs each, `/dev/ram0` and `/dev/ram1` respectively:
```bash
sudo modprobe brd rd_nr=2 rd_size=1048576
sudo insmod server.ko
echo "0 `sudo blockdev --getsz /dev/ram0` server /dev/ram0 1 2 0 true 12340" | sudo dmsetup create server1
echo "0 `sudo blockdev --getsz /dev/ram1` server /dev/ram1 1 2 1 false 12350 127.0.0.1 12340" | sudo dmsetup create server2
sudo fio --filename=/dev/mapper/server1 --readwrite=readwrite --bs=4k --direct=1 --loops=10 --name=servers
sudo fio --filename=/dev/mapper/server1 --readwrite=readwrite --bs=4k --direct=1 --fsync=1 --loops=10 --name=servers
```

You can find statistics about the running server by calling:
```bash
sudo dmsetup status server1
```
`server1` can be replaced with `server2` to check the status of the replica instead of the primary.
To see memory tracking statistics, you will need to uncomment `#define MEMORY_TRACKING`.


### Ping
Measure round trip network latency.  
Replace `<listen port>`, `<server addr>`, and `<server port>` with the desired ports. Only `<listen port>` is necessary.
```bash
echo "0 `sudo blockdev --getsz /dev/ram0` server /dev/ram0 <listen port> <server addr> <server port>" | sudo dmsetup create server
```

For example, set up ping locally between 2 ramdisks with 1GBs each, `/dev/ram0` and `/dev/ram1` respectively:
```bash
sudo modprobe brd rd_nr=2 rd_size=1048576
sudo insmod server.ko
echo "0 `sudo blockdev --getsz /dev/ram0` server /dev/ram0 12340" | sudo dmsetup create server1
echo "0 `sudo blockdev --getsz /dev/ram1` server /dev/ram1 12350 127.0.0.1 12340" | sudo dmsetup create server2
sudo ../tools/device_tester /dev/mapper/server1 write 
```

Pings are only triggered during fsync.  
The ping latency should be displayed in the outputs of `server1`.  
Note that the output will not be accurate if there are concurrent fsync.


### Integrity
Our custom integrity checker vs dm-integrity.

Load our encryption device mapper:
```bash
echo "0 `sudo blockdev --getsz /dev/ram0` hash /dev/ram0" | sudo dmsetup create hash
```

### Fsync
Replicating fsyncs vs flushing to disk.

Mount ext4. Replace `/dev/mapper/passthrough` with the device mapper's directory.
```bash
sudo mkfs.ext4 /dev/mapper/passthrough
sudo mount /dev/mapper/passthrough /mnt
```

### Rollbaccine
250000 = 1GB / 4KB, so we're allowing 1GB of memory to be allocated at any time.
```bash
sudo modprobe brd rd_nr=2 rd_size=1048576
sudo insmod rollbaccine.ko
echo "0 `sudo blockdev --getsz /dev/ram0` rollbaccine /dev/ram0 1 1 true abcdefghijklmnop 12340 2 127.0.0.1 12350" | sudo dmsetup create rollbaccine1
echo "0 `sudo blockdev --getsz /dev/ram1` rollbaccine /dev/ram1 2 1 false abcdefghijklmnop 12350 1 127.0.0.1 12340" | sudo dmsetup create rollbaccine2
sudo fio --filename=/dev/mapper/rollbaccine1 --readwrite=readwrite --bs=4k --direct=1 --loops=10 --name=rollbaccine
```


## Testing writes/reads to block device
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
If the block device is correct, then you should see the following outputs:
```
Wrote to file: Hello, world!
Read from file: Hello, world!
```


# Running on Azure

## Setup

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

## Launching VMs and cleaning up

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

## Plotting results

To plot the results, run the following command:

```bash
python3 plot_fio_results.py
```

This will create a `graphs` directory and save the bar graphs to it.


## Testing against ACE

We verify that the backup contains disk that can be used to recover consistently with [ACE](https://github.com/utsaslab/crashmonkey/blob/master/docs/Ace.md).
We execute tests generated by ACE with [xfstests](https://github.com/kdave/xfstests), running them over the primary, and checking that the backup has the same state.
To run the tests yourself, run the following command:

```bash
python3 src/tools/benchmarking/ace/ace.py
```