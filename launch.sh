#!/bin/bash
#
#  Launch VMs in Azure
#
print_usage() {
    echo "Usage: $0 -b <benchmark> -s <system> -n <numVMs>"
    echo "  -b: Benchmark name, one of {fio, filebench, postgres, hdfs, nimble_hdfs}"
    echo "  -s: System name, one of {UNREPLICATED, DM, REPLICATED, ROLLBACCINE}"
    echo "  -n: Number of VMs to launch"
}

while getopts 'b:s:n:' flag; do
  case ${flag} in
    b) BENCHMARK=${OPTARG} ;;
    s) SYSTEM=${OPTARG} ;;
    n) NUM_VMS=${OPTARG} ;;
    *) print_usage
       exit 1;;
  esac
done

NAME=$BENCHMARK-$SYSTEM
# Replace the subscription ID with your own; you can find it by going to the Azure Portal and clicking "Subscriptions"
SUBSCRIPTION_ID=ab9141a2-bb86-4f08-bd87-49b164a2ac4b
# The location is in North Europe, zone 3, because David's initial testing in [tee-benchmark](https://github.com/davidchuyaya/tee-benchmark) in 2023 revealed that it had the lowest network latency between nodes.
LOCATION=northeurope
# LOCATION=westus2
ZONE=3
# We must specify the sizes of the VMs that we intend to launch under `intent-vm-sizes`. We use the [DCadsv5](https://learn.microsoft.com/en-us/azure/virtual-machines/dcasv5-dcadsv5-series) series, which are general purpose, AMD SEV-SNP machines with temp disk.
VM_SIZE=Standard_DC16as_v5
VM_SIZE_TEMP_DISK=Standard_DC16ads_v5
# VM_SIZE=Standard_D16as_v5
# VM_SIZE_TEMP_DISK=Standard_D16ads_v5
# Set managed disk size (GB) to same size as temp disk
MANAGED_DISK_SIZE=600
USERNAME=$(whoami)
STORAGE_FILE=$BENCHMARK-$SYSTEM-storage.json
VM1_FILE=$BENCHMARK-$SYSTEM-vm1.json
VM2_FILE=$BENCHMARK-$SYSTEM-vm2.json

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
  --intent-vm-sizes $VM_SIZE $VM_SIZE_TEMP_DISK

if [ $BENCHMARK = "nimble_hdfs" ]; then
    echo "Creating storage account: rollbaccinenimble"
    az storage account create -n rollbaccinenimble -g $NAME-group -l $LOCATION --sku Standard_LRS
    az storage account keys list -n rollbaccinenimble -g $NAME-group > $STORAGE_FILE
fi

# Append a unique int to the end of each VM's name. Incremented at the end of launch_vm.
UNIQUE_ID=0

# Parameters: $1 = count, $2 = vm_size, $3 = output name, $4 = additional params
launch_vm () {
    if [ $1 -gt 1 ]; then
        COUNT='--count '$1
    else # Reset COUNT in case some other invocation set it
        COUNT=''
    fi

    echo "Launching $1 $2 VMs"

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
    #     --size $2 \
    #     --enable-secure-boot false \
    #     --image Canonical:ubuntu-24_04-lts:server:latest $COUNT $4 > $3

    az vm create \
    --resource-group $NAME-group \
    --name $NAME-$UNIQUE_ID \
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
    --size $2 \
    --priority Spot \
    --max-price -1 \
    --eviction-policy Delete \
    --image Canonical:ubuntu-24_04-lts:cvm:latest \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type VMGuestStateOnly \
    --enable-secure-boot false \
    --enable-vtpm $COUNT $4 > $3

    (($UNIQUE_ID++))
}

# Launch the right number of VMs with temp/managed disk
if [ $SYSTEM = "ROLLBACCINE" ]; then
    launch_vm 2 $VM_SIZE_TEMP_DISK $VM1_FILE
    REMAINING_VMS=$(($NUM_VMS - 2))
elif [ $SYSTEM = "REPLICATED" ]; then
    launch_vm 1 $VM_SIZE $VM1_FILE "--data-disk-sizes-gb $MANAGED_DISK_SIZE --data-disk-caching None"
    REMAINING_VMS=$(($NUM_VMS - 1))
else
    launch_vm 1 $VM_SIZE_TEMP_DISK $VM1_FILE
    REMAINING_VMS=$(($NUM_VMS - 1))
fi

# Launch remaining VMs without any disk
if [ $REMAINING_VMS -gt 0 ]; then
    launch_vm $REMAINING_VMS $VM_SIZE $VM2_FILE
fi

echo "Sleeping for 10 seconds to make sure the VMs are ready by the time this script finishes"
sleep 10