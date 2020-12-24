#!/bin/bash

rm -rf certs

export PASS='topsecretpassword'
export INTER_PASS="lesstopsecretpassword"

#create root certificate
mkdir certs certs/ca
cd certs/ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
cd ../..
cp openssl-root.cnf certs/ca/openssl-root.cnf
cp openssl-root2.cnf certs/ca/openssl-root2.cnf
cd certs/ca
openssl genpkey -out private/ca.key.pem -outform PEM -pass env:PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:4096
chmod 400 private/ca.key.pem
openssl req -config openssl-root.cnf -key private/ca.key.pem -keyform PEM -passin env:PASS -out certs/ca.cert.pem -passout env:PASS -new -x509 -days 7300 -sha256 -extensions v3_ca -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=Root Cert'
chmod 444 certs/ca.cert.pem
openssl x509 -noout -text -in certs/ca.cert.pem
cd ../..

#create intermediate certificate
mkdir certs/ca/intermediate
cd certs/ca/intermediate
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber
cd ../../..
cp openssl-inter.cnf certs/ca/intermediate/openssl-inter.cnf
cp openssl-inter2.cnf certs/ca/intermediate/openssl-inter2.cnf
cd certs/ca
openssl genpkey -out intermediate/private/intermediate.key.pem -outform PEM -pass env:INTER_PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:4096
chmod 400 intermediate/private/intermediate.key.pem
cd intermediate
openssl req -config openssl-inter.cnf -key private/intermediate.key.pem -keyform PEM -passin env:INTER_PASS -out csr/intermediate.csr.pem -passout env:INTER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=Intermediate Cert'
cd ..
openssl ca -batch -config openssl-root.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem -passin env:PASS
chmod 444 intermediate/certs/intermediate.cert.pem
openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem
cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
chmod 444 intermediate/certs/ca-chain.cert.pem

#create another intermediate certificate, which can be used to increase certificate chain length
openssl genpkey -out intermediate/private/intermediate2.key.pem -outform PEM -pass env:INTER_PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:4096
cd intermediate
openssl req -config openssl-inter.cnf -key private/intermediate2.key.pem -keyform PEM -passin env:INTER_PASS -out csr/intermediate2.csr.pem -passout env:INTER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=Intermediate Cert 2'
cd ..
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate2.csr.pem -out intermediate/certs/intermediate2.cert.pem -passin env:INTER_PASS
chmod 444 intermediate/certs/intermediate2.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/intermediate2.cert.pem
cat intermediate/certs/intermediate2.cert.pem intermediate/certs/ca-chain.cert.pem > intermediate/certs/ca-chain2.cert.pem
chmod 444 intermediate/certs/ca-chain2.cert.pem

# create even more intermediate certificates which can be used to generate valid client certs with excessive intermediate length
openssl genpkey -out intermediate/private/intermediate3.key.pem -outform PEM -pass env:INTER_PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:4096
cd intermediate
openssl req -config openssl-inter.cnf -key private/intermediate3.key.pem -keyform PEM -passin env:INTER_PASS -out csr/intermediate3.csr.pem -passout env:INTER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=Intermediate Cert 3'
cd ..
openssl ca -batch -config openssl-root2.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate3.csr.pem -out intermediate/certs/intermediate3.cert.pem -passin env:PASS
chmod 444 intermediate/certs/intermediate3.cert.pem
openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate3.cert.pem
cat intermediate/certs/intermediate3.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain3.cert.pem
chmod 444 intermediate/certs/ca-chain3.cert.pem
openssl genpkey -out intermediate/private/intermediate4.key.pem -outform PEM -pass env:INTER_PASS -aes256 -algorithm RSA -pkeyopt rsa_keygen_bits:4096
cd intermediate
openssl req -config openssl-inter.cnf -key private/intermediate4.key.pem -keyform PEM -passin env:INTER_PASS -out csr/intermediate4.csr.pem -passout env:INTER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=Intermediate Cert 4'
cd ..
sed s/intermediate.cert.pem/intermediate3.cert.pem/ <intermediate/openssl-inter.cnf >intermediate/openssl.inter.cnf
mv intermediate/openssl.inter.cnf intermediate/openssl-inter.cnf
sed s/intermediate.key.pem/intermediate3.key.pem/ <intermediate/openssl-inter.cnf >intermediate/openssl.inter.cnf
mv intermediate/openssl.inter.cnf intermediate/openssl-inter.cnf
openssl ca -batch -config intermediate/openssl-inter.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate4.csr.pem -out intermediate/certs/intermediate4.cert.pem -passin env:INTER_PASS
chmod 444 intermediate/certs/intermediate4.cert.pem
openssl verify -CAfile intermediate/certs/ca-chain3.cert.pem intermediate/certs/intermediate4.cert.pem
cat intermediate/certs/intermediate4.cert.pem intermediate/certs/ca-chain3.cert.pem > intermediate/certs/ca-chain4.cert.pem
chmod 444 intermediate/certs/ca-chain4.cert.pem
sed s/intermediate3.cert.pem/intermediate.cert.pem/ <intermediate/openssl-inter.cnf >intermediate/openssl.inter.cnf
mv intermediate/openssl.inter.cnf intermediate/openssl-inter.cnf
sed s/intermediate3.key.pem/intermediate.key.pem/ <intermediate/openssl-inter.cnf >intermediate/openssl.inter.cnf
mv intermediate/openssl.inter.cnf intermediate/openssl-inter.cnf

#create an expired intermediate certificate
ytd=$(printf "%s00Z" $(date +%Y%m%d%H%M --date='-1 day'))
yrago=$(printf "%s00Z" "$(date +%Y%m%d%H%M --date='-366 days')")
cd intermediate
openssl req -config openssl-inter.cnf -key private/intermediate.key.pem -keyform PEM -passin env:INTER_PASS -out csr/intermediate-expired.csr.pem -passout env:INTER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=Intermediate Cert Expired'
cd ..
openssl ca -batch -config openssl-root.cnf -extensions v3_intermediate_ca -startdate $yrago -enddate $ytd -notext -md sha256 -in intermediate/csr/intermediate-expired.csr.pem -out intermediate/certs/intermediate-expired.cert.pem -passin env:PASS
chmod 444 intermediate/certs/intermediate-expired.cert.pem
cat intermediate/certs/intermediate-expired.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain-expired.cert.pem
chmod 444 intermediate/certs/ca-chain-expired.cert.pem

#create a second intermediate cert to see what happens if the root is the same but the intermediate is different
cd intermediate
openssl req -config openssl-inter.cnf -key private/intermediate.key.pem -keyform PEM -passin env:INTER_PASS -out csr/intermediate_2.csr.pem -passout env:INTER_PASS -new -sha256 -subj '/C=US/ST=New York/O=COMS4181 Hw2/CN=Intermediate Cert Secondary'
cd ..
openssl ca -batch -config openssl-root.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate_2.csr.pem -out intermediate/certs/intermediate_2.cert.pem -passin env:PASS
chmod 444 intermediate/certs/intermediate_2.cert.pem
openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate_2.cert.pem
cat intermediate/certs/intermediate_2.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain_2.cert.pem
chmod 444 intermediate/certs/ca-chain_2.cert.pem