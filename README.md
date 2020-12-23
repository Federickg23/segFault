# segFault

Basically, the server side will accept requests, but the requests must indicate what the client wants each time. 

So server should, for `getcert`, lets say: 

```
method = read_https_request()
if method == getcert:
  user, password = read_https_request()
  import login
  if login.verify(user, password) == 0:
    send_https_response( "INVALID LOGIN" )
  else:
    cert = generate_certificate(user + password)
    send_https_response(cert)
    ### code to save cert on server ###
```

On the client side, it should somehow send the http request formatted properly, indicating the method, password, and user.
Then when it recieves the certificate (if response isn't an error) as a string, it just stores that into a file (cert.pem) 
