# Development setup

- [Setup](#setup)
- [Everyday development](#everyday-development)
- [Benchmarking](#benchmarking)


## Setup
Create a Ubuntu 20.04 LTS VM locally in order to compile and install the kernel module. Containers will not suffice; [kernel modules cannot be installed on containers](https://stackoverflow.com/q/62455239/4028758). I installed [UTM](https://mac.getutm.app/).

### Creating the VM with UTM
Download a [Ubuntu 20.04 LTS image](https://releases.ubuntu.com/focal/). I downloaded the server install image since I don't need the GUI.

Configure the VM:
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
- Wait until the install finishes, then select "Reboot now"
- In UTM, select CD/DVD and clear (this simulates ejecting disk)
- Enter your username and password

Start the SSH server on the VM:
```bash
sudo apt install -y openssh-server
sudo service ssh restart
```

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

To use VSCode in the VM, click the blue >< box in VSCode's bottom left corner, select "Connect to Host", and select "localvm". Install the necessary extensions (C++, Github copilot).


### Setting up the VM
Install the necessary packages:
```bash
sudo apt update
sudo apt install -y build-essential
```
[Install the GitHub CLI](https://github.com/cli/cli/blob/trunk/docs/install_linux.md#debian-ubuntu-linux-raspberry-pi-os-apt) so you can push changes after developing in the VM.

Outside the VM, run the following so we don't need to re-enter the password every time we SSH into the VM:
```bash
ssh-copy-id localvm
```


## Everyday development
After modifying the kernel module, compile it with and install it with:
```bash
cd src
make
sudo insmod rollbaccine.ko
```

> [!TIP]  
> To view the outputs of your module, execute `sudo dmesg | tail -10`. To see all loaded kernel modules, run `sudo lsmod`.


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
Create an Azure VM with a Ubuntu 22.04 image and at least 8 cores.
Turn off Secure Boot so we can load kernel modules.

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
sudo cryptsetup open --type luks /dev/ram0 secure
sudo fio --filename=/dev/mapper/secure --readwrite=readwrite --bs=4k --direct=1 --loops=2 --name=secure
```

Measure the throughput of our custom encrypting device mapper.


### Integrity
Our custom integrity checker vs dm-integrity.

### Fsync
Replicating fsyncs vs flushing to disk.

