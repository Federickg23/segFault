## OpenSSL Setup & Tests

### Directions
First, to create the required certificates and set up the server/client directories:

`./setup-all.sh` 

This concludes the creation of the root certificate, intermediate certificate, and certificates 2a-2d. In addition,
this includes additional intermediate certificates and client certificates (most of which are not usable) for
testing purposes.

To run the server-client SSL connection tests (note that running these tests may take several minutes as a result of
sleep calls in the test scripts; this is to ensure the server has been set up by the time the client attempts
to connect):

`./run-tests.sh`

This produces log files in `certs\ca\server\server` and `certs\ca\client\client`. For simplicity's sake, we refer to 
all directions assuming a base directory of `certs\ca` from here on.

If the script file has permission denied, run `chmod +x [file]`. (I dunno why this sometimes happens)

### Certificates Created

#### 2a. A web server certificate
The creation of the web server certificate follows the directions from the given link, and is located at
`server\certs\server.cert.pem`

#### 2b. A web client certificate
Similar to 2a, the web client certificate is located at `client\certs\client.cert.pem`, and follows the directions
from the link.

#### 2c. A certificate suitable for encrypting files
We create a new section in the intermediate configuration called encryption-cert; this section lists a keyUsage 
extension of only keyEncipherment and dataEncipherment (indicating that it is to be used to encrypt data). This
certificate is created in `other\certs\other-enc.cert.pem`.

#### 2d. A certificate suitable for signing files
Similarly, we create a section called signing-cert with a keyUsage of only digitalSignature. This certificate
is created in `other\certs\other-sign.cert.pem`

### Testing
Each separate category of tests is run as its own script file `tests-[test-no].sh` and can be individually run. Each
test script runs 1 or more related tests. 

All tests produce two sets of output, one for the server and the client; the output of test number test-no can be found 
in `server/server/test-testno` and `client/client/test-testno`, in matching log text files that contain the output of
both stdout and stderr for the server and the client respectively. 

Each test begins by starting an openssl server as a background process, with appropriate server flags per the test.
We wait 5 seconds (to ensure the server is running), then start a client and attempt to connect to the server (also 
with varying client flags per the test). If the connection is successful, we run a single command to fetch the 
`index.html` file, which is a simple blank HTML file that just contains a "Hello World!"
paragraph element. If we are able to successfully connect and fetch the corresponding file, the client's log will
contain the server's full certificate chain and the full contents of `index.html`. The server's corresponding log
file will contain `FILE:index.html` at or near the end. If the connection is not successful, the full contents of
`index.html` will not be retrieved, and both the server and the client will show some error statuses. Because by 
default, OpenSSL doesn't close connections on verification errors, we always run with `-verify_return_error` 
enabled on both the server and the client.

#### Test 1: Base Case
This case uses the default web server/client certificates generated in 2a/2b, and the `ca-chain.cert.pem` generated
as part of creating the intermediate certificate for the server & client's CA files, and should therefore work with no
issues.

#### Test 2: -Verify vs -verify and failing to present a client certificate
The s_server man page indicates that -Verify requires the client to present a certificate, while -verify simply 
requests the client to present a certificate. Test 2 contains 2 parts: in part 1, we use the -Verify flag, and fail
to present a certificate as a client. As expected, this produces an error on the server side that the client did not 
produce a certificate. In part 2, we use the -verify flag instead, and the server accepts the connection without issue.

#### Test 3: Certificates must come from a trusted source
The -CAfile flag on both the client and the server defines the trusted certificates for the client and server
respectively. If we don't specify the -CAfile or -CApath flags, s_server and s_client instead default to the system's
default, which will certainly not contain our root certificate as a trusted certificate.

In part 1, we fail to specify a CA file for the server; this leads to the server returning err 19 (self-signed
certificate in chain) because it doesn't trust the root certificate. Similarly, in part 2, we fail to specify a CA file
for the client, which causes the client to instead return err 19. 

#### Test 4: -CAfile must contain the root
The CAfile must contain the root certificate, or else the client/server respectively are actually unable to set
themselves up (in the case of the client, the client actually requires the full chain or it's unable to set itself
up). In part 1 and part 3, we give the client & server respectively the intermediate certificate, and they respectively
produce errno 2, unable to get local issuer certificate while attempting to validate their own certificates.
In part 2, we give the server the root certificate, which succeeds.

#### Test 5: Other certificate validity
Interestingly, although it is suggested that web servers should reject client certificates created with CA:true as a
'best practice', s_server does not do so; if we give the client the intermediate certificate, the server accepts the
certificate.

#### Test 6: Certificate KeyUsage Extension must match intended purpose
The keyUsage and extendedKeyUsage extensions determine what the certificate is permitted to be used for. A SSL client 
certificate, must include digitalSignature in its keyUsage and clientAuth in its extendedKeyUsage, or the certificate
is not considered valid for use as a SSL client cert.

In part 1, we create a client certificate which is not marked for digitalSignature and attempt to use it to connect
to the server. The server returns err 26, indicating the certificate's purpose is not correct for its usage. Similarly,
in part 2, we mark a certificate for digitalSignature, but do not mark its extendedKeyUsage as clientAuth, causing
the same error.

However, if we fail to specify these fields, the server assumes the certificate is okay to be used as a client
certificate; in part 3, we specify a keyUsage of digitalSignature, but have no extendedKeyUsage, while in part 4,
we have no keyUsage or extendedKeyUsage. Both certificates are accepted by the server.

For the server, a certificate must have keyUsage as keyEncipherment and extendedKeyUsage as serverAuth, but we do not
test for this.

#### Test 7: Intermediate certificate pathlen constraints must be honored
When we created the intermediate certificate, we assigned it a basicConstraint of pathlen=0, which means that the
certificate can only sign end user certs. If we create another intermediate certificate from this intermediate cert,
and then create an end user cert from that certificate, the end user certificate fails as a client certificate and 
the server returns an error number of 25, pathlen violated.

#### Test 8: The certificate must be valid right now
We create a certificate that was valid until yesterday, and another certificate that won't be valid until next year,
in parts 1 and 2 respectively. As expected, neither certificate can be used because their validity period is not 
current; in part 1, the server returns error 10, expired, and in part 2 the server returns error 9, not yet valid.

#### Test 9: A wrong certificate won't be verified
The certificate contains information to validate itself/protect its integrity. If we edit a single byte of the
certificate, the certificate will be considered invalid. We pass a modified client certificate, and the server
as expected rejects the certificate.

#### Test 10: A certificate cannot be signed by an expired certificate
Similar to test 8, no certificate in the chain can have a validity period that doesn't include now; if we create an
intermediate certificate that is already expired and use it to sign a certificate that is not expired, the server
still returns error 10: expired certificate.

#### Test 11: Different intermediate certificates
If we create multiple valid intermediate certificates, and then create valid end user certificates that have a
different intermediate between the server and the client, the server should recognize the client's certificate, and vice
versa, if the client and server have the correct CA files.

In part 1, both the client and the server use the original ca-chain file; this results in an error as the server cannot
verify the client's certificate as it uses a different intermediate. In part 2, the server switches to the other 
ca-chain file, and the server is able to verify the client. In part 3, the client switches to the other ca-chain file, 
but this causes a verification failure on the client's side instead, as the server's cert is using the original
intermediate certificate.

#### Test 12: Verify Depth
If we create a valid end user certificate which has N intermediate certificates but the server's verify depth is less
than N, then the server will reject the certificate anyways with err no 22: certificate chain is too long.

#### Test 13: Hostnames and subject alternative names
If we specifically ask to verify the hostname, the common name listed for the certificate must match the requested
hostname. The subject alt name field is also used for verifying hostnames; a request for hostname can be satisfied
if it matches one of the listed subject alt names instead of the common name.
In part 1, the server requests a specific hostname from the client, which does not match the client hostname; this 
produces errno 62. Similarly, in part 3, the client requests a specific hostname from the server, which does not match
and produces the same error. In part 2 however, the client requests a specific hostname which doesn't match the
server's common name but does match one of the listed subject alt names, and the request succeeds.
