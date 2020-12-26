#!/bin/bash
set -e

id=$1

if [[ $# != 1 ]]
then
	echo "Usage: $0 [id]"
	exit 1
fi

openssl genrsa -aes256 \
	-out private_keys/$id.key.pem 2048

chmod 400 private_keys/$id.key.pem
