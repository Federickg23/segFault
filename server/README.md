### Usage
Currently, most of the structure should already exist. There should be a:
1. `mail` folder that holds all the mailboxes,
2. `cert` folder that holds the server's certificate
3. `clientcert` folder that holds clients' certificates, from `getcert` function.
4. `hashed_password` folder that holds clients' login passwords
5. `key` folder that holds the server's private key.

Should `mail` or `hashed_passwords` be gone, there are two respective shellscripts you can run to generate them again.
Note, running the hashed_passwords will reset all client's passwords to the default value, provided in `login.txt` in the
home directory. So if clients changed their passwords, but you remade the `hashed_passwords` structure, the clients should
be aware of their passwords set to default.


### server.cpp
The main file here is the server.cpp file. You can run `make` and then recieve the `server` executable. 

Run `./server`, and it will look for the certificate "localhost.cert.pem" and key "localhost.key.pem". Of course, you 
may regenerate the certificates via the home directory's `certificates` folder, but currently the password is "server".

### Details
Inside the code, server sets up the connections. I recommend starting with the `main()` function to investigate it's usage.

After establishing the connections and certificates, you'll see towards the end there is a line that extracts the method from
the message, and then sends an http response based on that method.

Inside the `send_http_response` function, that is whre most of the logic happens. Only 4 methods will be supported, and each one
has their own logic in the if-statements.


