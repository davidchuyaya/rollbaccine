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
echo "share	rollbaccine	9p	trans=virtio,version=9p2000.L,rw,_netdev,nofail	0	0" | sudo tee -a /etc/fstab
```

For convenience SSHing into the VM, add the following to your machine's `~/.ssh/config`:
```bash
Host localvm
  HostName 192.168.64.3
  User davidchu
```
Replacing the IP address and username with your VM's.

To use VSCode in the VM, click the blue >< box in VSCode's bottom left corner, select "Connect to Host", and select "localvm". Install the necessary extensions.


### Setting up the VM
Install the necessary packages:
```bash
sudo apt update
sudo apt install -y build-essential
```
[Install the GitHub CLI](https://github.com/cli/cli/blob/trunk/docs/install_linux.md#debian-ubuntu-linux-raspberry-pi-os-apt).

## Everyday development
After modifying the kernel module, compile it with:
```bash
cd src
make
```
Note that `Makefile` uses the headers from the `~/linux` directory, so it will only work for the Linux image above. If we want it to work for the VM we're running instructions from, we'll have to comment out that line and un-comment the line above it.

Copy the compiled module to the startup directory:
```bash
cp hello.ko ~/busybox/_install
find . | cpio -H newc -o | gzip > ../ramdisk.img
```

Now [run Linux](#running-linux), and load the module with:
```bash
insmod hello.ko
```

## Benchmarking
Create an Azure VM with a Ubuntu 22.04 image and at least 8 cores.
Turn off Secure Boot so we can load kernel modules.