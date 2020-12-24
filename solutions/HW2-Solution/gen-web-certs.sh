#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export CLIENT_PASS="topsecretclientpassword"
export OTHER_PASS="othertopsecretpassword"
export INTER_PASS="lesstopsecretpassword"

# generate web server certificate
cd certs/ca
mkdir server client server/private client/private server/certs client/certs server/csr client/csr other other/private other/csr other/certs
openssl genpkey -out server/private/server.key.pem -outform PEM -pass env:SERVER_PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
chmod 400 server/private/server.key.pem
openssl req -config intermediate/openssl-inter.cnf -key server/private/server.key.pem -keyform PEM -passin env:SERVER_PASS -out server/csr/server.csr.pem -passout env:SERVER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220.columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions server_cert -days 365 -notext -md sha256 -in server/csr/server.csr.pem -out server/certs/server.cert.pem -passin env:INTER_PASS
chmod 444 server/certs/server.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem server/certs/server.cert.pem
cp intermediate/certs/ca-chain.cert.pem server/certs/ca-chain.cert.pem
cp intermediate/certs/ca-chain_2.cert.pem server/certs/ca-chain_2.cert.pem
cp intermediate/certs/ca-chain-expired.cert.pem server/certs/ca-chain-expired.cert.pem

# generate web client certificate
openssl genpkey -out client/private/client.key.pem -outform PEM -pass env:CLIENT_PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
chmod 400 client/private/client.key.pem
openssl req -config intermediate/openssl-inter.cnf -key client/private/client.key.pem -keyform PEM -passin env:CLIENT_PASS -out client/csr/client.csr.pem -passout env:CLIENT_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220@columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions usr_cert -days 365 -notext -md sha256 -in client/csr/client.csr.pem -out client/certs/client.cert.pem -passin env:INTER_PASS
chmod 444 client/certs/client.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem client/certs/client.cert.pem
cp intermediate/certs/ca-chain.cert.pem client/certs/ca-chain.cert.pem
cp intermediate/certs/ca-chain_2.cert.pem client/certs/ca-chain_2.cert.pem
cp intermediate/certs/ca-chain-expired.cert.pem client/certs/ca-chain-expired.cert.pem

# generate encryption only and signing only certificates
openssl genpkey -out other/private/other.key.pem -outform PEM -pass env:OTHER_PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
chmod 400 other/private/other.key.pem
openssl req -config intermediate/openssl-inter.cnf -key other/private/other.key.pem -keyform PEM -passin env:OTHER_PASS -out other/csr/other-enc.csr.pem -passout env:OTHER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=Kai Lu Personal Enc Cert'
openssl req -config intermediate/openssl-inter.cnf -key other/private/other.key.pem -keyform PEM -passin env:OTHER_PASS -out other/csr/other-sign.csr.pem -passout env:OTHER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=Kai Lu Personal Signing Cert'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions encryption_cert -days 365 -notext -md sha256 -in other/csr/other-enc.csr.pem -out other/certs/other-enc.cert.pem -passin env:INTER_PASS
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions signing_cert -days 365 -notext -md sha256 -in other/csr/other-sign.csr.pem -out other/certs/other-sign.cert.pem -passin env:INTER_PASS
chmod 444 other/certs/other-enc.cert.pem
chmod 444 other/certs/other-sign.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem other/certs/other-enc.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem other/certs/other-sign.cert.pem

