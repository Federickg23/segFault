# segFault

### Usage 

You will mainly be interacting with `server` and `client` folder. Each folder has their respective README.

But, there is one thing that first must be set up - the server's certificates and the CA. Currently, it is setup.
But depending on when this is being read, the certificates may have expired.

1. `server/` holds all the files for the server end
2. `client/` holds all the files for the client end
3. `logins.txt` is an important file to reference for login usernames and passwords
4. `certificates` is a folder that holds the CA, Intermediate CA, and process to generate the server's certificates

### Default (Use as is right now)

Currently, the certificates should all be set up. So, you can proceed to `server/` first.

But, I want to point out the current passwords for the certificates:

For server: its "server"
For CA: its "root"
For Intermediate CA: its "intermediate"

The name of the certificates / keys are as such:

1. server runs on localhost, so the certificate is `localhost.cert.pem` and key is likewise
2. the intermediate CA has it's certificate as `intermediate.cert.pem`
3. the CA has it's certificate as `ca.cert.pem`

For more details on this fundemental certificate generation, proceed to the `certificates/` directory. 



