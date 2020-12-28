#!/bin/bash
set -e
export PASS=$1

openssl genrsa -aes256 \
	-passout env:PASS \
	-out dummy.txt 2048

