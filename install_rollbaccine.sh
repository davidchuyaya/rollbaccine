#!/bin/bash

sudo apt-get -qq update
sudo apt-get install -qq -y build-essential
git clone -q https://github.com/davidchuyaya/rollbaccine
cd rollbaccine/src
make --silent