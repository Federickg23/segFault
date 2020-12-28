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

echo "---------- Generating CSR --------------\n"
openssl req -config ../certificates/root/ca/intermediate/openssl.cnf \
	-key private_keys/$id.key.pem \
	-new -sha256 -out csr/$id.csr.pem
