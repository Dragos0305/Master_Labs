#!/bin/bash


openssl x509 -in ocw.crt -noout -dates
openssl x509 -in ocw.crt -noout -issuer
openssl x509 -in ocw.crt -noout -subject
openssl x509 -in ocw.crt -noout -pubkey


timeout 5 openssl s_client -connect www.google.com:443 -showcerts > google.crt
timeout 5 openssl s_client -connect www.amazon.com:443 -showcerts > amazon.crt
timeout 5 openssl s_client -connect www.microsoft.com:443 -showcerts > microsoft.crt
