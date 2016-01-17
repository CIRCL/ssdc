#!/bin/bash

set -e
set -x

seq 24 | parallel ./compute.py
