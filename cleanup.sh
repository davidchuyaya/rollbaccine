#!/bin/bash
#
#  Cleanup VMs in Azure
#
print_usage() {
    echo "Usage: $0 -b <benchmark> -s <system>"
    echo "  -b: Benchmark name, one of {fio, filebench, postgres, hdfs, nimble_hdfs}"
    echo "  -s: System name, one of {UNREPLICATED, DM, REPLICATED, ROLLBACCINE}"
}

while getopts 'b:s:' flag; do
  case ${flag} in
    b) BENCHMARK=${OPTARG} ;;
    s) SYSTEM=${OPTARG} ;;
    n) NUM_VMS=${OPTARG} ;;
    *) print_usage
       exit 1;;
  esac
done

NAME=$BENCHMARK-$SYSTEM
az group delete \
    -n $NAME-group \
    --yes --no-wait
# Use -f because storage.json may or may not exist, depending on whether the benchmark required it
rm -f storage.json
rm vm1.json
rm -f vm2.json
rm stdout.txt