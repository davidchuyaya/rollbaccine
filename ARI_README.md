# Instructions for SIGMOD evaluation
Please coordinate with other reviewers when running experiments to avoid interference and quota limits!
These instructions are tested on MacOS and should work on Linux and WSL as well.

## Azure CLI
- Install the Azure CLI by following instructions [here](https://github.com/davidchuyaya/rollbaccine#running-on-azure).
- Login using the Azure email and password given.
- Stop at "Launching VMs and cleaning up".

### Errors
If you see an error in the script, either reach out to me or run the cleanup command in the "Launching VMs and cleaning up" section.

## GCP CLI
- Install the GCP CLI by following instructions [here](https://github.com/davidchuyaya/rollbaccine#running-on-gcp).
- Login using the GCP email and password given.
- You do not need to enable the Compute Engine API; I have set that up for you.

### Errors
Similarly, don't run the `cleanup_gcp.sh` command unless the GCP-specific test (`python3 src/tools/benchmarking/postgres/postgres_gcp.py`) fails. 

## Begin evaluation
Run each of the commands [here](https://github.com/davidchuyaya/rollbaccine#evaluation).  
I recommend running at most 2 commands concurrently, because we have a limited VM quota. Each experiment should run for under an hour, and once complete, raw data files will be downloaded to a local `results` directory.

