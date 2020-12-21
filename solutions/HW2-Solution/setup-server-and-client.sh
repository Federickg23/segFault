#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export CLIENT_PASS="topsecretclientpassword"
export INTER_PASS="lesstopsecretpassword"

# setup server and logs
cd certs/ca
mkdir server/server
cd ../..
cp index.html certs/ca/server/server/index.html

# setup client and logs
cd certs/ca
mkdir client/client
printf 'GET /index.html HTTP/1.1\r\n' >client/client/command.txt

# create additional (bad) client certificates which can be used for testing
# a client certificate with CA:TRUE
openssl req -config intermediate/openssl-inter.cnf -key client/private/client.key.pem -keyform PEM -passin env:CLIENT_PASS -out client/csr/client_err_1.csr.pem -passout env:CLIENT_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220+1@columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions usr_cert_err_1 -days 365 -notext -md sha256 -in client/csr/client_err_1.csr.pem -out client/certs/client_err_1.cert.pem -passin env:INTER_PASS
chmod 444 client/certs/client_err_1.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem client/certs/client_err_1.cert.pem

# a client certificate without the correct key usage, but not marked as critical
openssl req -config intermediate/openssl-inter.cnf -key client/private/client.key.pem -keyform PEM -passin env:CLIENT_PASS -out client/csr/client_err_2.csr.pem -passout env:CLIENT_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220+2@columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions usr_cert_err_2 -days 365 -notext -md sha256 -in client/csr/client_err_2.csr.pem -out client/certs/client_err_2.cert.pem -passin env:INTER_PASS
chmod 444 client/certs/client_err_2.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem client/certs/client_err_2.cert.pem

# as above, but marked as critical
openssl req -config intermediate/openssl-inter.cnf -key client/private/client.key.pem -keyform PEM -passin env:CLIENT_PASS -out client/csr/client_err_3.csr.pem -passout env:CLIENT_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220+3@columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions usr_cert_err_3 -days 365 -notext -md sha256 -in client/csr/client_err_3.csr.pem -out client/certs/client_err_3.cert.pem -passin env:INTER_PASS
chmod 444 client/certs/client_err_3.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem client/certs/client_err_3.cert.pem

# as above, but with the extended key usage not marked as critical
openssl req -config intermediate/openssl-inter.cnf -key client/private/client.key.pem -keyform PEM -passin env:CLIENT_PASS -out client/csr/client_err_4.csr.pem -passout env:CLIENT_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220+4@columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions usr_cert_err_4 -days 365 -notext -md sha256 -in client/csr/client_err_4.csr.pem -out client/certs/client_err_4.cert.pem -passin env:INTER_PASS
chmod 444 client/certs/client_err_4.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem client/certs/client_err_4.cert.pem

# a certificate that doesn't take effect until tomorrow
ytd=$(printf "%s00Z" $(date +%Y%m%d%H%M --date='-1 day'))
yrago=$(printf "%s00Z" "$(date +%Y%m%d%H%M --date='-366 days')")
nxtyr=$(printf "%s00Z" "$(date +%Y%m%d%H%M --date='+365 days')")
nxtnxtyr=$(printf "%s00Z" "$(date +%Y%m%d%H%M --date='+730 days')")
openssl req -config intermediate/openssl-inter.cnf -key client/private/client.key.pem -keyform PEM -passin env:CLIENT_PASS -out client/csr/client_err_5.csr.pem -passout env:CLIENT_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220+5@columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions usr_cert -startdate $yrago -enddate $ytd -notext -md sha256 -in client/csr/client_err_5.csr.pem -out client/certs/client_err_5.cert.pem -passin env:INTER_PASS
chmod 444 client/certs/client_err_5.cert.pem
# openssl verify -CAfile intermediate/certs/ca-chain.cert.pem client/certs/client_err_5.cert.pem
# don't bother verifying either of these; since their dates are off, neither cert will be valid
openssl req -config intermediate/openssl-inter.cnf -key client/private/client.key.pem -keyform PEM -passin env:CLIENT_PASS -out client/csr/client_err_6.csr.pem -passout env:CLIENT_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220+6@columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions usr_cert -startdate $nxtyr -enddate $nxtnxtyr -notext -md sha256 -in client/csr/client_err_6.csr.pem -out client/certs/client_err_6.cert.pem -passin env:INTER_PASS
chmod 444 client/certs/client_err_6.cert.pem

# generate the same client and server certs, but with an intermediate certificate chain that's 2 certs long
openssl req -config intermediate/openssl-inter2.cnf -key client/private/client.key.pem -keyform PEM -passin env:CLIENT_PASS -out client/csr/client_err_7.csr.pem -passout env:CLIENT_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220+7@columbia.edu'
openssl ca -batch -config intermediate/openssl-inter2.cnf -extensions usr_cert -days 365 -notext -md sha256 -in client/csr/client_err_7.csr.pem -out client/certs/client_err_7.cert.pem -passin env:INTER_PASS
chmod 444 client/certs/client_err_7.cert.pem
# openssl verify -CAfile intermediate/certs/ca-chain2.cert.pem client/certs/client_err_7.cert.pem
# don't bother verifying these either; they're also bad because of path length constraint violations
openssl req -config intermediate/openssl-inter2.cnf -key server/private/server.key.pem -keyform PEM -passin env:SERVER_PASS -out server/csr/server_err.csr.pem -passout env:SERVER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220.2.columbia.edu'
openssl ca -batch -config intermediate/openssl-inter2.cnf -extensions server_cert -days 365 -notext -md sha256 -in server/csr/server_err.csr.pem -out server/certs/server_err.cert.pem -passin env:INTER_PASS
chmod 444 server/certs/server_err.cert.pem
# openssl verify -CAfile intermediate/certs/ca-chain2.cert.pem server/certs/server_err.cert.pem

# create a certificate that is slightly broken
sed -e '0,/a/ s/a/A/' <client/certs/client.cert.pem >client/certs/client_broken.cert.pem

# create a client certificate out of an expired intermediate certificate
sed s/intermediate.cert.pem/intermediate-expired.cert.pem/ <intermediate/openssl-inter.cnf >intermediate/openssl.inter.cnf
mv intermediate/openssl.inter.cnf intermediate/openssl-inter.cnf
openssl req -config intermediate/openssl-inter.cnf -key client/private/client.key.pem -keyform PEM -passin env:CLIENT_PASS -out client/csr/client_err_8.csr.pem -passout env:CLIENT_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220+8@columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions usr_cert -days 365 -notext -md sha256 -in client/csr/client_err_8.csr.pem -out client/certs/client_err_8.cert.pem -passin env:INTER_PASS
chmod 444 client/certs/client_err_8.cert.pem

# create a client certificate out of a valid but different intermediate certificate
sed s/intermediate-expired.cert.pem/intermediate_2.cert.pem/ <intermediate/openssl-inter.cnf >intermediate/openssl.inter.cnf
mv intermediate/openssl.inter.cnf intermediate/openssl-inter.cnf
openssl req -config intermediate/openssl-inter.cnf -key client/private/client.key.pem -keyform PEM -passin env:CLIENT_PASS -out client/csr/client_diff.csr.pem -passout env:CLIENT_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220+9@columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions usr_cert -days 365 -notext -md sha256 -in client/csr/client_diff.csr.pem -out client/certs/client_diff.cert.pem -passin env:INTER_PASS
chmod 444 client/certs/client_diff.cert.pem

# create a client certificate out of a valid intermediate cert, but the chain is too long
sed s/intermediate_2.cert.pem/intermediate4.cert.pem/ <intermediate/openssl-inter.cnf >intermediate/openssl.inter.cnf
mv intermediate/openssl.inter.cnf intermediate/openssl-inter.cnf
sed s/intermediate.key.pem/intermediate4.key.pem/ <intermediate/openssl-inter.cnf >intermediate/openssl.inter.cnf
mv intermediate/openssl.inter.cnf intermediate/openssl-inter.cnf
openssl req -config intermediate/openssl-inter.cnf -key client/private/client.key.pem -keyform PEM -passin env:CLIENT_PASS -out client/csr/client_long.csr.pem -passout env:CLIENT_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=kl3220+10@columbia.edu'
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions usr_cert -days 365 -notext -md sha256 -in client/csr/client_long.csr.pem -out client/certs/client_long.cert.pem -passin env:INTER_PASS
chmod 444 client/certs/client_long.cert.pem

sed s/intermediate4.cert.pem/intermediate.cert.pem/ <intermediate/openssl-inter.cnf >intermediate/openssl.inter.cnf
mv intermediate/openssl.inter.cnf intermediate/openssl-inter.cnf
sed s/intermediate4.key.pem/intermediate.key.pem/ <intermediate/openssl-inter.cnf >intermediate/openssl.inter.cnf
mv intermediate/openssl.inter.cnf intermediate/openssl-inter.cnf

