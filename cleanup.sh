#!/bin/bash
#
#  Cleanup VMs in Azure
#
print_usage() {
    echo "Usage: $0 -b <benchmark> -s <system> -e <extra str>"
    echo "  -b: Benchmark name, one of {fio, filebench, postgres, hdfs, nimble_hdfs}"
    echo "  -s: System name, one of {UNREPLICATED, DM, REPLICATED, ROLLBACCINE}"
    echo "  -e: Extra string to append to resource group name"
}

while getopts 'b:s:e:' flag; do
  case ${flag} in
    b) BENCHMARK=${OPTARG} ;;
    s) SYSTEM=${OPTARG} ;;
    e) EXTRA=${OPTARG} ;;
    *) print_usage
       exit 1;;
  esac
done

NAME=$BENCHMARK-$SYSTEM-$EXTRA
az group delete \
    -n $NAME-group \
    --yes --no-wait
# Use -f because storage.json may or may not exist, depending on whether the benchmark required it
rm -f $NAME-storage.json
rm $NAME-vm1.json
rm -f $NAME-vm2.json
rm $NAME-stdout.txt