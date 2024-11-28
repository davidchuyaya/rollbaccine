#!/bin/bash
#
#  Cleanup VMs in Azure
#
print_usage() {
    echo "Usage: $0 -i <id>"
    echo "  -i: Prefix ID for the resource group, VMs, etc"
}

while getopts 'i:' flag; do
  case ${flag} in
    i) NAME=${OPTARG} ;;
    *) print_usage
       exit 1;;
  esac
done

az group delete \
    -n $NAME-group \
    --yes --no-wait
rm storage.json
rm vms.json