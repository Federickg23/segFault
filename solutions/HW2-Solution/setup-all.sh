#!/bin/bash

chmod +x gen-certs.sh
chmod +x gen-web-certs.sh
chmod +x setup-server-and-client.sh

./gen-certs.sh
./gen-web-certs.sh
./setup-server-and-client.sh