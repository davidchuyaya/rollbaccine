#!/bin/bash

sudo apt-get update
sudo apt-get install -y build-essential
git clone https://github.com/davidchuyaya/rollbaccine
cd rollbaccine/src
make

# Unmount the default disk
sudo umount /dev/sdb1