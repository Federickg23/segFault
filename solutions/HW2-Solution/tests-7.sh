#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export CLIENT_PASS="topsecretclientpassword"

# test 7: the intermediate certificate was incorrectly used to sign another intermediate (violating the pathlen constraint)
# this certificate should not be usable
cd certs/ca/server/server
rm -rf test-7
mkdir test-7
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-7/togs.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
rm -rf test-7
mkdir test-7
openssl s_client -connect localhost:12345 -cert ../certs/client_err_7.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../../intermediate/certs/ca-chain2.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-7/logs.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
cd ../..
rm -f server/server/server-pid.pid