# Development setup
Create an Azure VM with a Ubuntu 22.04 image and at least 8 cores.
Turn off Secure Boot so we can load kernel modules.


## Linux dev environment setup
We will run Linux in QEMU so whenever our device mapper crashes, it doesn't take down the VM.
This section was created by referencing [Setting Up an Environment for Writing Linux Kernel Modules](https://www.youtube.com/watch?v=tPs1uRqOnlk) and [Build and run minimal Linux / Busybox systems in Qemu](https://gist.github.com/chrisdone/02e165a0004be33734ac2334f215380e).

SSH into your VM and run the following commands.

### Install necessary dependencies
```bash
sudo apt update
sudo apt install -y build-essential
# Required for building linux kernel (so we can test without crashing the kernel)
sudo apt install -y libssl-dev flex libelf-dev bison qemu-kvm
```
You will be prompted to restart packagekit.service. Let it restart.

### Build the Linux kernel
```bash
git clone --depth=1 https://github.com/torvalds/linux.git
cd linux
make defconfig
scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS
make -j8
```
You'll need to press enter a few times to generate some certificates. This will take a while. `-j8` makes it faster but I'm not sure if it works with the certificate generation stuff, so you can try running it without `-j8` at first.

### Build Busybox
Clone this repo so we can copy `init`, the startup script for Linux.
```bash
cd ~
git clone https://github.com/davidchuyaya/rollbaccine.git
```

Now build Busybox.
```bash
cd ~
git clone --depth=1 https://github.com/mirror/busybox.git
cd busybox
make defconfig
make menuconfig
# Select Settings -> Build static binary
make -j8
make install
cd _install
cp ~/rollbaccine/init .
chmod +x init
```

Stop tty from printing a lot of errors on startup.
```bash
cd ~/busybox/_install
mkdir etc
cp ../examples/inittab etc
vim etc/inittab 
```
Comment out lines starting with tty in etc/inittab.

Allow Linux to access the network.
```bash
mkdir -p usr/share/udhcpc
cp ../examples/udhcp/simple.script usr/share/udhcpc/default.script
```

Copy all these files into the Linux image.
```bash
cd ~/busybox/_install
find . | cpio -H newc -o | gzip > ../ramdisk.img
```

> [!TIP]
> Run the line above any time the startup directory or init script changes. You can also add files to `_install` for them to be visible to Linux.


### Running Linux
```bash
cd ~/linux
qemu-system-x86_64 -nographic -kernel arch/x86_64/boot/bzImage --append "console=tty0 console=ttyS0" -initrd ../busybox/ramdisk.img -nic user,model=rtl8139,hostfwd=tcp::5556-:8080
```