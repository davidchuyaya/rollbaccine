#!/bin/bash

# Copy files to /etc
sudo cp ~/*.pem /etc
sudo cp ~/tlshd.conf /etc
# Install
sudo apt-get update
sudo apt-get install -y build-essential automake pkg-config cmake-data gnutls-bin libgnutls28-dev libkeyutils-dev libglib2.0-dev libnl-3-dev libnl-genl-3-dev
git clone https://github.com/oracle/ktls-utils
cd ktls-utils
sudo ./autogen.sh
sudo ./configure --with-systemd
sudo make
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now tlshd