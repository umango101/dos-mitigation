#!/bin/bash

cat $1 | grep "failed=" | awk -F "|" '{print $2}'
