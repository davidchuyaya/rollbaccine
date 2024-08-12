#!/bin/bash
#
#  Cleanup VMs in Azure
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

az group delete \
    --name $NAME-group \
    --yes --no-wait
rm *.pem
rm vms.json