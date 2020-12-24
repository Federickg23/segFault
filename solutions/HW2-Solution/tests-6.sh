#!/bin/bash

export SERVER_PASS="topsecretserverpassword"
export CLIENT_PASS="topsecretclientpassword"

# test 6: if a certificate is not marked for usage as a client for SSL (ie, it doesn't have digitalSignature), it should not be accepted
# part 1: a certificate not marked for digitalSignature will not be able to connect successfully
cd certs/ca/server/server
rm -rf test-6
mkdir test-6
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-6/togs-1.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
rm -rf test-6
mkdir test-6
openssl s_client -connect localhost:12345 -cert ../certs/client_err_2.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-6/logs-1.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
cd ../..
rm -f server/server/server-pid.pid

# part 2: the certificate is marked for digitalSignature, but the extended key usage is not marked for client auth, which similarly fails
cd server/server
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-6/togs-2.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
openssl s_client -connect localhost:12345 -cert ../certs/client_err_3.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-6/logs-2.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
rm -f server-pid.pid

# part 3: the certificate is marked for digitalSignature and has no extended key usage options
# this is okay in comparison to above
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-6/togs-3.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
openssl s_client -connect localhost:12345 -cert ../certs/client_err_4.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-6/logs-3.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
rm -f server-pid.pid

# part 4: the certificate simply is not marked for usage
# if you don't mark it for anything, it's assumed to be okay
openssl s_server -accept 12345 -cert ../certs/server.cert.pem -certform PEM -Verify 4 -verify_return_error -key ../private/server.key.pem -keyform PEM -pass env:SERVER_PASS -CAfile ../certs/ca-chain.cert.pem -www -HTTP >test-6/togs-4.txt 2>&1 &
echo $! > server-pid.pid
sleep 5
cd ../../client/client
openssl s_client -connect localhost:12345 -cert ../certs/client_err_1.cert.pem -certform PEM -key ../private/client.key.pem -keyform PEM -pass env:CLIENT_PASS -CAfile ../certs/ca-chain.cert.pem -verify 4 -verify_return_error -ign_eof <command.txt >test-6/logs-4.txt 2>&1
cd ../../server/server
pkill -F server-pid.pid
rm -f server-pid.pid