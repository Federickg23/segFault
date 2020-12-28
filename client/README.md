### Usage

The clients feature the 4 required functions, but also a few important directories:

1. `certs` will hold all the client certificates. Obviously in the real world, all clients dont share the same space - but for our code and organizing, they are all there.
2. `private_keys` will hold all the client private keys. Same 'obviously' reason as above
3. `public_keys` will hold all the client's public keys. Same 'obviously' reason as above


Clients need to first get a CSR, which is done via the `gen-csr.sh` script.

Simply run `./gen-csr.sh [username]`

You will be asked to choose a password for your private key. In addition, when generating the CSR, you MUST use your username as the common name, 
otherwise your certificate will have issues when trying to send messages.


### getcert

Initially, you want to get your certificate! The server only has usernames and passwords provided in the `logins.txt` file in the
home directory, so do not try to log in with a user that does not exist.

The usage is:

`./getcert [username] [password] [path/to/csr]`

Pretty straight forward. The certificate will be stored then in the certs folder. (The server will retain a copy).


### changepw

Very straight forward. Simply run:

`./changepw [username] [password] [new_password]`


### sendmsg

The message format will follow that as done in the homeworks. But, your certificate will also be sent over and verified. So you would need
to include that too. (Currently, does not parse the messages for recipients and all. There seems to be an issue with decryption - just sends the whole message).

`./sendmsg [path/to/cert] [path/to/message]`


### recvmsg
First, you need to have mail in your inbox. If not, that is okay - you will get a response saying you have none.

Typically for testing, you can try to use sendmsg to send a message to yourself.

The usage is:

`./recvmsg [path/to/cert] [path/to/private_key]

### Details
Each .cpp file generally works the same and has a lot of the same code. We didn't have the chance to make a very friendly design and import
similar functions from a universal file. 

Instead, the idea is to focus on the `main()` first. Towards the end, you will see how the message is being built. The format of the HTTPS message
is crucial, since the server expects that kind of format. Generally, the `send_http_request` is all the same except the method being added.
