#!/bin/bash

set -e
ct=../$1
id=$2

if [[ $# -lt 2 ]]
then
	echo "Usage: $0 cert_type identifier"
	echo "cert_type possible choices: client or server"
	echo "identifier should be a name to uniquely identify the certificate (ex: server -> www.example.com)"
	exit 1
fi

if [[ $1 == "client" ]]
then
	opt=usr_cert

elif [[ $1 == "server" ]]
then
	opt=server_cert
else 
	echo "cert_type possible choices: client, server, encrypt, sign"
	exit 1
fi


if [[ ! -d "$ct" ]]
then
	mkdir $ct $ct/certs $ct/key
	echo "Directory $ct made"
	echo "Directory $ct/certs made"
	echo "Directory $ct/key made"
fi

if [[ ! -d "$ct/certs" ]]
then
	mkdir $ct/certs
	echo "Directory $ct/certs made"
fi

if [[ ! -d "$ct/key" ]]
then
	mkdir $ct/key
	echo "Directory $ct/key made"
fi

echo "# --- Generating $opt Private Key -------------- #"
RI=./root/ca/intermediate

if [[ -f "$RI/private/$id.key.pem" ]]
then
	echo "Private key already exists. It is likely the certification does 
	as well. For the purposes of this assignment, handling overwrites and
	revokes is not supported. Therefore, use a new identifier. Otherwise,
	recreate the root CA and start all over."

	exit 0
fi

openssl genrsa -aes256 \
      	-out $RI/private/$id.key.pem 2048
	
chmod 400 $RI/private/$id.key.pem
cp $RI/private/$id.key.pem $ct/key

echo "# --- Generating CSR ------------------------------- #"
openssl req -config $RI/openssl.cnf \
      -key $RI/private/$id.key.pem \
      -new -sha256 -out $RI/csr/$id.csr.pem

echo "# --- Signing Certificate ------------------------- #"

openssl ca -config $RI/openssl.cnf \
      -extensions $opt -days 375 -notext -md sha256 \
      -in $RI/csr/$id.csr.pem \
      -out $RI/certs/$id.cert.pem

cp $RI/certs/$id.cert.pem $ct/certs
echo "Certification copied to $ct/certs"

chmod 444 $RI/certs/$id.cert.pem
chmod 444 $ct/certs/$id.cert.pem

if [[ ! -f "$ct/certs/ca-chain.cert.pem" ]]
then

	cp $RI/certs/ca-chain.cert.pem $ct/certs
	echo "Copied Certificate Chain to $ct/certs"
else
	echo 'Certificate Chain already exists'

fi
