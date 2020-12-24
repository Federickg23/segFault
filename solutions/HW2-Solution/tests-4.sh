#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export CLIENT_PASS="topsecretclientpassword"

# test 4: the CA file has to contain the root of the verification chain;
# if we use the intermediate cert for the CA file, we will be unable to find the issuer of the intermediate cert
cd certs/ca/server/server
rm -rf test-4
mkdir test-4
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 1 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-4/togs-1.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
rm -rf test-4
mkdir test-4
openssl s_client -connect localhost:12345 -cert ../certs/client.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../../intermediate/certs/intermediate.cert.pem -verify 1 -verify_return_error -ign_eof <command.txt >test-4/logs-1.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
cd ../..
rm -f server/server/server-pid.pid

# part 2: likewise, try using the root cert as a CAfile
cd server/server
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 1 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../../certs/ca.cert.pem -www -HTTP >test-4/togs-2.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
openssl s_client -connect localhost:12345 -cert ../certs/client.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 1 -verify_return_error -ign_eof <command.txt >test-4/logs-2.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
rm -f server-pid.pid

# part 3: similar to part 1, but with the CA file for the client and server flipped
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 1 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../../intermediate/certs/intermediate.cert.pem -www -HTTP >test-4/togs-3.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
openssl s_client -connect localhost:12345 -cert ../certs/client.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 1 -verify_return_error -ign_eof <command.txt >test-4/logs-3.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
rm -f server-pid.pid
