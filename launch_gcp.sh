#!/bin/bash
#
#  Launch a Rollbaccine backup VM in GCP
#
print_usage() {
    echo "Usage: $0 -i <IP address> -r <resource group> -p <project id>"
    echo "  -i: IP address of the Rollbaccine primary VM in Azure"
    echo "  -r: Name of the resource group in Azure, without the '-group' suffix"
    echo "  -p: Project ID in GCP"
}

set -x

while getopts 'i:r:p:' flag; do
  case ${flag} in
    i) PRIMARY_IP=${OPTARG} ;;
    r) AZURE_RESOURCE_GROUP=${OPTARG} ;;
    p) PROJECT_ID=${OPTARG} ;;
    *) print_usage
       exit 1;;
  esac
done

NETWORK_NAME=rollbaccine-network

gcloud compute networks create $NETWORK_NAME \
    --subnet-mode=auto

# Allow communication with Azure
# Ports correspond to ones used when launching Rollbaccine in run_benchmarks.py
gcloud compute firewall-rules create azure-to-gcp \
    --network=$NETWORK_NAME \
    --allow=tcp,icmp \
    --source-ranges=$PRIMARY_IP/32

# Allow SSH access
gcloud compute firewall-rules create ssh \
    --network=$NETWORK_NAME \
    --allow=tcp:22 \
    --source-ranges=0.0.0.0/0

# Note: Local SSD will always be of size 375GB (cannot be configured)
gcloud compute instances create rollbaccine-backup \
    --confidential-compute-type=SEV_SNP \
    --machine-type=n2d-standard-16 \
    --min-cpu-platform="AMD Milan" \
    --maintenance-policy=TERMINATE \
    --zone=europe-west4-a \
    --network=$NETWORK_NAME \
    --image-project=ubuntu-os-cloud \
    --image-family=ubuntu-2404-lts-amd64 \
    --project=$PROJECT_ID \
    --local-ssd=interface=NVME \
    --no-shielded-secure-boot > gcp.txt

# Allow SSH access
gcloud compute config-ssh

# gcp.txt is of the following format:
# NAME                ZONE            MACHINE_TYPE     PREEMPTIBLE  INTERNAL_IP  EXTERNAL_IP  STATUS
# rollbaccine-backup  europe-west4-a  n2d-standard-16               10.164.0.2   34.6.48.60   RUNNING
GCP_VM_IP=$(cat gcp.txt | grep rollbaccine-backup | awk '{print $5}')

# For Azure, allow communication with GCP using the public IP just created
# Assume the 0th VM is the Rollbaccine primary
az network nsg rule create \
    -g $AZURE_RESOURCE_GROUP-group \
    --nsg-name $AZURE_RESOURCE_GROUP-0NSG \
    -n gcp-to-azure \
    --priority 100 \
    --source-address-prefixes $GCP_VM_IP \
    --destination-port-ranges '*'