#!/bin/bash

# Ping the domain and check if it responds
if ping -c 1 -W 1 $1 > /dev/null 2>&1
then
    # Domain is alive
    echo 1
else
    # Domain is not alive
    echo 0
fi
