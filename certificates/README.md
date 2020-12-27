# Certificates Assignment (HW2)
Michael Grandel - mg3856


## Initialize

NOTE: This README is in depth, and usage is the same, but certificates are not necesarrily stored in the
same places described. When making the server certificate, it will end up in the `segFault/server/cert/` directory,
not in the intermediate directory here.

client certificates are not used.


The base file structure should be:

\_ generate_ca.sh
\_ get_certificate.sh
\_ clean.sh
\_ server
\_ client


To begin, we need to generate a CA. This is done via the `generate_ca.sh` shell script.

Run `# ./generate_ca.sh `

You will be prompted a set of questions to set up the CA key and Certificatae, and 
the Intermediate Key and Certificate.

After that, the folder `./root/` should appear and is populated with configuration
files and the necessary CA/Intermediate files. You won't need to interact with this
folder.


## Getting Certificates

Now, you would like to produce some certificates. This is done via `get_certificate.sh`

The usage is:

`# ./get_certificate.sh type id `

`type` can only be one of 2 arguments: client, server

Hence, you will get the certificate back for the appropriate type.


`id` is the identification you wish to use - something you will be putting in the Common Name field when
generating a CSR.

So if you're a server, then `id` should be `www.example.com`; or 'localhost' in our case. 
If you're a client, then your username. Ultimatley,this is just used to identify the csr, certificate, and key files created.

--------------------- NEED TO CHANGE THIS, SINCE THERE'S changepw FUNCTION --------------------------------
Note: if a certificate/key exists for the id, you would not be able to use the same id. As such, you should 
use a new id. Of course, this could've been extended to support different types with the same id, or even
allow same ids but as long as Certificate details are different... but that is more of a 'nice to have' in a
real application rather than assignment. 

If you really need to reset because you tried to delete some files, you should run `# ./clean.sh`. 
Note, that the index and serial files in the root reflect the certificates - so modifying files
is not trivial. Hence a fresh restart is best (which means the root too. That's what `clean.sh` does)
----------------------------------------------------------------------------------------------------------

Certificates and Keys will be added to respective directories. Here is an example:

`# ./get_certificate.sh server www.myserver.com `

So, you will be propmted questions to create a key and a CSR for a server certificate.
Note, you should enter www.myserver.com as the Common Name.

I didn't support adding custom SubjectAltNames, since that is also a nice to have in a real application,
but there are 3 default ones. You'll see them in the CSR. If you need to change them, then you'd have to
change the config file. This is in `./root/ca/intermediate/openssl.cnf`, and in the [server_cert] section.

Note, the configuration is created in `generate_ca.sh`, so if you want a more permanent change, you can alter
it in the shell script.

Once the CSR is approved, the key and certificate is stored in the `root/ca/intermediate` folder, but also 
copied to the `server` folder. Here will be the new file structure:

server/
\_ certs
	\_ www.myserver.com.cert.pem
	\_ ca-chain.cert.pem
\_ key
	\_ www.myserver.com.key.pem

So, the certification, certificate chain, and key are copied to the server directory.

Note: when testing, these files are copies! When we launch the server/client in the next step, they reference the
files in their folder. NOT in the intermediate folder. Hence, compromising the intermediate files does not affect
the server/client authentication. This is okay, since the server isnt doing CRL/OCSP to consistently fetch and 
check that the certification in intermediate isn't compromised. 

If you do want to pull the files from the intermediate, you'd need to manually copy them over. Just note, there
are permissions to work around (cert in server folder can't be overwritten. So you'd need to delete it first)


You can make multiple certifications. Suppose you do this again, with a different id and Common Name.

 
`# ./get_certificate.sh server another.server.com `

This will result in:

server/
\_ certs
	\_ www.myserver.com.cert.pem
	\_ another.server.com.cert.pem
	\_ ca-chain.cert.pem
\_ key
	\_ www.myserver.com.key.pem
	\_ another.server.com.key.pem


## Launching Server/Client


So let's say you now have server and client certificates. You can now run a HTTPS between them.

Open two VM instances. For the server, navigate to `server/` and for the client, navigate to `client/`

For both, you will run the `launch.sh` shell.

For the server, you'll have to specify the id you want to use. Let's use our server file structure above.

`# ./launch.sh www.myserver.com`

This will search for the certificate, key, and ca-chain in the `server/certs` and `server/key` 
You will be asked to enter the key password and the server will be launched.
It also creates 3 example files in the directory `files`, which the client can request.

The server expects clients to present a valid certificate. If not, the request will not be processed.
This is where we can begin to manipulate tests described in tests section.
The server listens on port 4433

Now you need to launch the client in the client VM.

There are two ways to launch the client. Either send an HTTP request, or view the server certificate.
One option was to send the HTTP request and also obtain the encrypted certificate response, but I decided
to just split this into two seperate requests and have the certificate request decrypt and format the 
certificate (its passed into x509)

You can see those details in the shell script. But here's how you run it:

`# ./launch.sh id ` - for the default HTTP request: GET files/ex1.txt
`# ./launch.sh id show_cert` to view the server certificate.

The client connects to localhost:4433 

The id is uses the same way in server - it points to the cert, ca-chain, and key file in the client folder.

If you did the default HTTP request, you will see in your output the ca-chain verification, and also
the ex1.txt file contents (Example file 1).

If you want to redirect this output to a file so you can see it seprately, simply edit the `launch.sh`
by redirecting the output. Add ` > example.txt` to the end of the `openssl s_client ... ` command.

------------------------------ COULD MODIFY THIS TO SUPPORT CUSTOM REQUESTS -----------------------------
If you want to change the request, you an also modify it in the `launch.sh` file.

I did not support custom requests as arguments, again, because its a nice-to-have in real applciation. 
The goal for using OpenSSL and working with certificates is what this assignment tests.
---------------------------------------------------------------------------------------------------------
