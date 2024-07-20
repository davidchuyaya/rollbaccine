# Development setup

- [Setup](#setup)
- [Everyday development](#everyday-development)
- [Benchmarking](#benchmarking)

Create a Ubuntu 24.04 LTS VM locally in order to compile and install the kernel module. Containers will not suffice; [kernel modules cannot be installed on containers](https://stackoverflow.com/q/62455239/4028758). The 24.04 version is required for in-kernel TLS.

Download a [Ubuntu 24.04 LTS image](https://ubuntu.com/download/server). I downloaded the server install image since I don't need the GUI.

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
python3 .vscode/generate_compdb.py -O /lib/modules/6.8.0-38-generic/build $PWD
```

Replace `6.8.0-38-generic` with the output of `uname -r` on the VM.


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
Create an Azure VM with a Ubuntu 24.04 image and at least 8 cores.
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
Replace `<listen port>`, `<server port 1>`, and `<server port 2>` with the desired ports, where you can supply a varying number of server ports, depending on how many servers this node should connect to.
```bash
echo "0 `sudo blockdev --getsz /dev/ram0` server /dev/ram0 <f> <n> <id> <is_leader> <listen port> <server port 1> <server port 2>" | sudo dmsetup create server
```

For example, set up networking locally between 2 ramdisks with 1GBs each, `/dev/ram0` and `/dev/ram1` respectively:
```bash
sudo modprobe brd rd_nr=2 rd_size=1048576
sudo insmod server.ko
echo "0 `sudo blockdev --getsz /dev/ram0` server /dev/ram0 1 2 0 true 12340" | sudo dmsetup create server1
echo "0 `sudo blockdev --getsz /dev/ram1` server /dev/ram1 1 2 1 false 12350 12340" | sudo dmsetup create server2
sudo fio --filename=/dev/mapper/server1 --readwrite=readwrite --bs=4k --direct=1 --loops=10 --name=servers
sudo fio --filename=/dev/mapper/server1 --readwrite=readwrite --bs=4k --loops=10 --name=servers
```

#### TLS
To enable/disable TLS, comment out the `#define TLS` line in [server.c](src/network/server.c).  
Run the following instructions *before* setting up networking.

Create the certificates for TLS, if the files don't already exist in the [network](network) directory. As we create more replicas, we'll have to add all their certificates to the `tls_certs.pem` file by concatenating them. Replace `localhost` with the address of the node:
```bash
openssl req -x509 -newkey rsa:4096 -keyout 0_key.pem -out 0_cert.pem -sha256 -days 365 -nodes -nodes -subj "/C=US/ST=CA/L=Berkeley/O=UCB/OU=SkyLab/CN=localhost"
openssl req -x509 -newkey rsa:4096 -keyout 1_key.pem -out 1_cert.pem -sha256 -days 365 -nodes -nodes -subj "/C=US/ST=CA/L=Berkeley/O=UCB/OU=SkyLab/CN=localhost"
cat 0_cert.pem 1_cert.pem > tls_certs.pem
```

Install [ktls-utils](https://github.com/oracle/ktls-utils), since kTLS itself can't actually perform the handshake; [it requires an application in userspace to do it](https://docs.kernel.org/networking/tls-handshake.html#user-handshake-agent) for security concerns [[1](https://lwn.net/Articles/892216/)][[2](https://lwn.net/Articles/896746/)]:
```bash
sudo apt install -y automake pkg-config cmake-data gnutls-bin libgnutls28-dev libkeyutils-dev libglib2.0-dev libnl-3-dev libnl-genl-3-dev
git clone https://github.com/oracle/ktls-utils
cd ktls-utils
sudo ./autogen.sh
sudo ./configure --with-systemd
sudo make
sudo make install
sudo cp *.pem /etc # Move all the certificates to the right directory
sudo cp tlshd.conf /etc # Move the config
sudo systemctl daemon-reload
sudo systemctl enable --now tlshd
```
This is known to work for commit e55cefda944595fd83b609eba7ad8f819fa1c9d3. Roll it back with `git checkout`.

If ktls-utils stops working, check its logs with `journalctl -b` and filter for "tls".


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