# SNI Router

Go based SNI router. Intercepts the SNI header, then serves the correct certificates and routes to the right backend based on a lookup.

## Useful commands

* SSL Client

    openssl s_client -connect localhost:9999 -servername test.com

* SSL Server

    openssl s_server -accept 443 -cert normal_cert.pem -key normal_key.ky -servername xyz.com -cert2 sni_cert.pem -key2 sni_key.ky

* Generate Keys

    openssl genrsa -des3 -out server.key 2048
    openssl req -new -key server.key -out server.csr
    cp server.key server.key.org
    openssl rsa -in server.key.org -out server.key
    openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
