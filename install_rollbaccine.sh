#!/bin/bash

sudo apt-get update -qq
sudo apt-get install -qq -y build-essential
git clone -q https://github.com/davidchuyaya/rollbaccine
cd rollbaccine/src
make --silent