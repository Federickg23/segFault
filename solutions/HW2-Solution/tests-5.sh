#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export CLIENT_PASS="topsecretclientpassword"
export INTER_PASS="lesstopsecretpassword"

# test 5: interestingly enough, any certificate which is in the certificate chain is considered a valid certificate
# using the intermediate cert for the client will not produce any errors

cd certs/ca/server/server
rm -rf test-5
mkdir test-5
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-5/togs.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
rm -rf test-5
mkdir test-5
openssl s_client -connect localhost:12345 -cert ../../intermediate/certs/intermediate.cert.pem -certform PEM -key ../../intermediate/private/intermediate.key.pem -keyform PEM -pass env:INTER_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-5/logs.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
cd ../..
rm -f server/server/server-pid.pid