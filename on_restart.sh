#!/bin/bash
# Script to run on each machine bootup

# Unmount the default disk
sudo umount /dev/sdb1
# Change the default scheduler so writes get merged at the backup
echo 'mq-deadline' | sudo tee -a /sys/block/sdb/queue/scheduler