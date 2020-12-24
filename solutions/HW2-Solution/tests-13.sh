#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export CLIENT_PASS="topsecretclientpassword"

# test 13: verify hostname
# part 1: standard hostname verification with a bad hostname will fail
cd certs/ca/server/server
rm -rf test-13
mkdir test-13
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -verify_hostname notkl3220@columbia.edu -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-13/togs-1.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
rm -rf test-13
mkdir test-13
openssl s_client -connect localhost:12345 -cert ../certs/client.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-13/logs-1.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
cd ../..
rm -f server/server/server-pid.pid

# part 2: try using the subject alt name for the server
cd server/server
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-13/togs-2.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
openssl s_client -connect localhost:12345 -cert ../certs/client.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -verify_hostname ftp.kl3220.columbia.edu -ign_eof <command.txt >test-13/logs-2.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
rm -f server-pid.pid

# part 3: try using a non-alt name for the server
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-13/togs-3.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
openssl s_client -connect localhost:12345 -cert ../certs/client.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -verify_hostname fake.kl3220.columbia.edu -ign_eof <command.txt >test-13/logs-3.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
rm -f server-pid.pid