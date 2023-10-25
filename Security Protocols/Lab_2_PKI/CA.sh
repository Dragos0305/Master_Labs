#!/bin/bash

mkdir -p keys
touch keys/index.txt
echo "01" > keys/serial

#  Build a CA key (once only). It is valid for ten years, starting from the time it was generated
openssl req -days 3650 -nodes -new -x509 -keyout keys/ca.key -out keys/ca.crt -config openssl.cnf

# Build a request for a cert that will be valid for ten years
openssl req -nodes -new -keyout keys/server.key -out keys/server.csr -config openssl.cnf


# Sign the cert request with our ca, creating a cert/key pair
openssl ca -days 3650 -out keys/server.crt -in keys/server.csr -extensions server -config openssl.cnf

# Delete any .old files created in this process, to avoid future file creation errors
rm keys/*.old

# Build a request for a cert that will be valid for ten years
openssl req -nodes -new -keyout keys/client.key -out keys/client.csr -config openssl.cnf


# Sign the cert request with our ca, creating a cert/key pair
openssl ca -days 3650 -out keys/client.crt -in keys/client.csr -config openssl.cnf

# Delete any .old files created in this process, to avoid future file creation errors
rm keys/*.old


