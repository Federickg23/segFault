#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export CLIENT_PASS="topsecretclientpassword"

# test 12: if the server's verify depth is 1, but the client's intermediate chain is too long
# verification will fail
cd certs/ca/server/server
rm -rf test-12
mkdir test-12
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 1 -verify_depth 1 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../../intermediate/certs/ca-chain4.cert.pem -www -HTTP >test-12/togs.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
rm -rf test-12
mkdir test-12
openssl s_client -connect localhost:12345 -cert ../certs/client_long.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-12/logs.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
cd ../..
rm -f server/server/server-pid.pid