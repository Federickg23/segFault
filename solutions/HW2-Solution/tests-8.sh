#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export CLIENT_PASS="topsecretclientpassword"

# test 8: the time of validity has to be now
# part 1: expired certificates don't work
cd certs/ca/server/server
rm -rf test-8
mkdir test-8
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-8/togs-1.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
rm -rf test-8
mkdir test-8
openssl s_client -connect localhost:12345 -cert ../certs/client_err_5.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-8/logs-1.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
cd ../..
rm -f server/server/server-pid.pid

# part 2: a certificate that won't be valid until next year also shouldn't work
cd server/server
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-8/togs-2.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
openssl s_client -connect localhost:12345 -cert ../certs/client_err_6.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-8/logs-2.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
rm -f server-pid.pid