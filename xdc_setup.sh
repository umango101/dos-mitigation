#!/bin/bash

# Install Dependencies
apt update
apt install -y ansible nano man-db python3.10-venv zip net-tools
yes | unminimize