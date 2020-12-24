#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export CLIENT_PASS="topsecretclientpassword"

# test 11: different intermediate (but valid) certs for the server and the client
# part 1: use the original CA file
# this will fail, because the server's cert chain won't contain the client's intermediate
cd certs/ca/server/server
rm -rf test-11
mkdir test-11
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-11/togs-1.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
rm -rf test-11
mkdir test-11
openssl s_client -connect localhost:12345 -cert ../certs/client_diff.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-11/logs-1.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
cd ../..
rm -f server/server/server-pid.pid

# part 2: make the server use the CA file that contains the secondary intermediate
# this will work, because the certificate chain contains the client's intermediate
cd server/server
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain_2.cert.pem -www -HTTP >test-11/togs-2.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
openssl s_client -connect localhost:12345 -cert ../certs/client_diff.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-11/logs-2.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
rm -f server-pid.pid

# part 3: both sides have the CA file with the secondary intermediate
# this will also fail, because the client's cert chain won't contain the server's intermediate
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain_2.cert.pem -www -HTTP >test-11/togs-3.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
openssl s_client -connect localhost:12345 -cert ../certs/client_diff.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain_2.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-11/logs-3.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
rm -f server-pid.pid