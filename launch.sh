#!/bin/bash
#
#  Launch VMs in Azure
#
print_usage() {
    echo "Usage: $0 -n <name>"
}

while getopts 'n:' flag; do
  case ${flag} in
    n) NAME=${OPTARG} ;;
    *) print_usage
       exit 1;;
  esac
done

# Replace the subscription ID with your own; you can find it by going to the Azure Portal and clicking "Subscriptions"
SUBSCRIPTION_ID=ab9141a2-bb86-4f08-bd87-49b164a2ac4b
# The location is in North Europe, zone 3, because David's initial testing in [tee-benchmark](https://github.com/davidchuyaya/tee-benchmark) in 2023 revealed that it had the lowest network latency between nodes.
LOCATION=northeurope
ZONE=3
# We must specify the sizes of the VMs that we intend to launch under `intent-vm-sizes`. We use the [DCadsv5](https://learn.microsoft.com/en-us/azure/virtual-machines/dcasv5-dcadsv5-series) series, which are general purpose, AMD SEV-SNP machines with temp disk.
VM_SIZE=Standard_DC16ads_v5
USERNAME=davidchu
NUM_VMS=2

# 1. Launch the VMs

echo "Creating resource group: "$NAME"-group"
az group create \
  --subscription $SUBSCRIPTION_ID \
  --name $NAME-group \
  --location $LOCATION 
  
echo "Creating PPG: $NAME-ppg"
az ppg create \
  --resource-group $NAME-group \
  --name $NAME-ppg \
  --location $LOCATION \
  --zone $ZONE \
  --intent-vm-sizes $VM_SIZE

echo "Launching $NUM_VMS VMs"
az vm create \
    --resource-group $NAME-group \
    --name $NAME \
    --admin-username $USERNAME \
    --generate-ssh-keys \
    --public-ip-sku Standard \
    --nic-delete-option Delete \
    --os-disk-delete-option Delete \
    --data-disk-delete-option Delete \
    --accelerated-networking false \
    --ppg $NAME-ppg \
    --location $LOCATION \
    --zone $ZONE \
    --size $VM_SIZE \
    --image Canonical:ubuntu-24_04-lts:cvm:latest \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type VMGuestStateOnly \
    --enable-secure-boot false \
    --enable-vtpm \
    --count $NUM_VMS > vms.json

# 2. Get VM IP addresses

PUBLIC_IP_0=$(jq -r '.[] | select(.name=="'$NAME'0") | .publicIps' vms.json)
PUBLIC_IP_1=$(jq -r '.[] | select(.name=="'$NAME'1") | .publicIps' vms.json)
PRIVATE_IP_0=$(jq -r '.[] | select(.name=="'$NAME'0") | .privateIps' vms.json)
PRIVATE_IP_1=$(jq -r '.[] | select(.name=="'$NAME'1") | .privateIps' vms.json)

echo "Public IP 0: "$PUBLIC_IP_0
echo "Public IP 1: "$PUBLIC_IP_1
echo "Private IP 0: "$PRIVATE_IP_0
echo "Private IP 1: "$PRIVATE_IP_1

echo "Installing rollbaccine on servers"
ssh -o StrictHostKeyChecking=no $USERNAME@$PUBLIC_IP_0 "bash -s" -- < install_rollbaccine.sh
ssh -o StrictHostKeyChecking=no $USERNAME@$PUBLIC_IP_1 "bash -s" -- < install_rollbaccine.sh

echo "You should now ssh into the servers and launch rollbaccine. Increase 250000 (the max number of pages that can be in memory) depending on the circumstances:"
echo "ssh $USERNAME@$PUBLIC_IP_0"
echo "sudo umount /dev/sdb1"
echo "cd rollbaccine/src"
echo "sudo insmod rollbaccine.ko"
echo 'echo "0 `sudo blockdev --getsz /dev/sdb1` rollbaccine /dev/sdb1 1 2 0 true 250000 abcdefghijklmnop 12340" | sudo dmsetup create rollbaccine1'
echo ""
echo "ssh $USERNAME@$PUBLIC_IP_1"
echo "sudo umount /dev/sdb1"
echo "cd rollbaccine/src"
echo "sudo insmod rollbaccine.ko"
echo 'echo "0 `sudo blockdev --getsz /dev/sdb1` rollbaccine /dev/sdb1 1 2 1 false 250000 abcdefghijklmnop 12350 $PRIVATE_IP_0 12340" | sudo dmsetup create rollbaccine2'
