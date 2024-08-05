#!/bin/bash

sudo apt-get update
sudo apt-get install -y build-essential
git clone https://github.com/davidchuyaya/rollbaccine
# TODO: Replace installing server with install the entire rollbaccine
cd rollbaccine/src/network
make