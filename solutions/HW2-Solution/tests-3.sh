#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export CLIENT_PASS="topsecretclientpassword"

# test 3: if the certificate is not from a trusted entity, an error should occur
# part 1: if we don't give a CAfile to the server, it should default to the system's default
# the self-signed cert that the client will attempt to present should not work in this case
# server should complain that a self-signed cert is in the chain, and the client should show an error
cd certs/ca/server/server
rm -rf test-3
mkdir test-3
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -www -HTTP >test-3/togs-1.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
rm -rf test-3
mkdir test-3
openssl s_client -connect localhost:12345 -cert ../certs/client.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-3/logs-1.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
cd ../..
rm -f server/server/server-pid.pid

# part 2: similarly, if we don't give a CAfile to the client, it should default to the system's default
# same error, in the other direction
cd server/server
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-3/togs-2.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
openssl s_client -connect localhost:12345 -cert ../certs/client.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -verify 4 -verify_return_error -ign_eof <command.txt >test-3/logs-2.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
rm -f server-pid.pid