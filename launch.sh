#!/bin/bash
#
#  Launch VMs in Azure
#
print_usage() {
    echo "Usage: $0 -i <id> -n <numVMs> [-s]"
    echo "  -i: Prefix ID for the resource group, VMs, etc"
    echo "  -n: Number of VMs to launch"
    echo "  -s: Whether to create a Azure storage under the same resource group"
}

while getopts 'i:n:s' flag; do
  case ${flag} in
    i) NAME=${OPTARG} ;;
    n) NUM_VMS=${OPTARG} ;;
    s) STORAGE=true ;;
    *) print_usage
       exit 1;;
  esac
done

# Replace the subscription ID with your own; you can find it by going to the Azure Portal and clicking "Subscriptions"
SUBSCRIPTION_ID=99c3b15b-bec1-49de-85be-849e7a51cce5
# The location is in North Europe, zone 3, because David's initial testing in [tee-benchmark](https://github.com/davidchuyaya/tee-benchmark) in 2023 revealed that it had the lowest network latency between nodes.
# LOCATION=northeurope
LOCATION=westus2
ZONE=3
# We must specify the sizes of the VMs that we intend to launch under `intent-vm-sizes`. We use the [DCadsv5](https://learn.microsoft.com/en-us/azure/virtual-machines/dcasv5-dcadsv5-series) series, which are general purpose, AMD SEV-SNP machines with temp disk.
# VM_SIZE=Standard_DC16ads_v5
VM_SIZE=Standard_D16ads_v5
USERNAME=$(whoami)

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

if [ $STORAGE ]; then
    echo "Creating storage account: rollbaccine$NAME"
    az storage account create -n rollbaccine$NAME -g $NAME-group -l $LOCATION --sku Standard_LRS
    az storage account keys list -n rollbaccine$NAME -g $NAME-group > storage.json
fi

# Only use the --count parameter if there is more than 1 VM, otherwise the script will fail.
if [ $NUM_VMS -gt 1 ]; then
    COUNT_NUM_VMS='--count '$NUM_VMS
fi

# echo "Launching $NUM_VMS Confidential VMs"
# az vm create \
#     --resource-group $NAME-group \
#     --name $NAME \
#     --admin-username $USERNAME \
#     --generate-ssh-keys \
#     --public-ip-sku Standard \
#     --nic-delete-option Delete \
#     --os-disk-delete-option Delete \
#     --data-disk-delete-option Delete \
#     --accelerated-networking false \
#     --ppg $NAME-ppg \
#     --location $LOCATION \
#     --zone $ZONE \
#     --size $VM_SIZE \
#     --image Canonical:ubuntu-24_04-lts:cvm:latest \
#     --security-type ConfidentialVM \
#     --os-disk-security-encryption-type VMGuestStateOnly \
#     --enable-secure-boot false \
#     --enable-vtpm $COUNT_NUM_VMS > vms.json

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
    --image Canonical:ubuntu-24_04-lts:server:latest $COUNT_NUM_VMS > vms.json

