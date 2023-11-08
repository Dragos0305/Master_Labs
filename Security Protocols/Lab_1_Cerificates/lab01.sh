#!/bin/bash

echo "[+]Laboratory 1 starts here"

echo "[+]Generate certificate request\n Command: openssl req -new -newkey rsa:1024 -nodes -keyout [filename].pem -out [filename].pem"
openssl req -new -newkey rsa:1024 -nodes -keyout dstratulat.key.pem -out dstratulat.req.pem

echo "[+]Generate self-signed certificate based on certificate request created earlier"
openssl x509 -req -days 365 -in dstratulat.req.pem -signkey dstratulat.key.pem -sha256 -out dstratulat.crt

echo "[+]Get certificate for www.google.com"
openssl s_client -connect www.google.com:443 -showcerts < /dev/null | openssl x509 -outform pem > google.crt

echo "[+]Get certificate for www.hackthebox.com"
openssl s_client -connect www.github.com:443 -showcerts < /dev/null | openssl x509 -outform pem > hackthebox.crt

echo "[+]Get certificate for www.github.com"
openssl s_client -connect www.github.com:443 -showcerts < /dev/null | openssl x509 -outform pem > github.crt


