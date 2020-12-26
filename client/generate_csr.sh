#!/bin/bash
set -e

id=$1

if [[ $# != 1 ]]
then
	echo "Usage: $0 [id]"
	exit 1
fi

# The config file for client is the same as the one for
# intermediate CA. Yes, I can copy over just the req part
# for security reasons, but that here makes no difference

# Infact, actually, this should indeed be the case for 
# permission control. I should copy over just the req, since
# clients/users should not be able to access the CA files at
# all.

openssl req -config ../certificates/root/ca/intermediate/openssl.cnf \
	-key  private_keys/$id.key.pem \
	-new -sha256 -out csr/$id.csr.pem

