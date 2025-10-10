#!/bin/bash
#
#  Cleanup VMs in GCP
#

gcloud compute instances delete rollbaccine-backup --zone=europe-west4-a --quiet
gcloud compute firewall-rules delete azure-to-gcp ssh --quiet
gcloud compute networks delete rollbaccine-network --quiet
rm gcp.txt