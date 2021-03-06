#!/bin/sh

set -xe

rm -rf quic-rsa/ quic-ecdsa/
mkdir -p quic-rsa/ quic-ecdsa/

openssl req -nodes \
          -x509 \
          -days 3650 \
          -newkey rsa:2048 \
          -keyout rsa/ca.key \
          -out rsa/ca.cert \
          -sha256 \
          -batch \
          -subj "/CN=GLA RSA CA"

openssl req -nodes \
          -newkey rsa:2048 \
          -keyout rsa/inter.key \
          -out rsa/inter.req \
          -sha256 \
          -batch \
          -subj "/CN=GLA RSA level 2 intermediate"

openssl req -nodes \
          -newkey rsa:2048 \
          -keyout rsa/end.key \
          -out rsa/end.req \
          -sha256 \
          -batch \
          -subj "/CN=quic-rust.com"

openssl rsa \
          -in rsa/end.key \
          -out rsa/end.rsa

openssl req -nodes \
          -newkey rsa:2560 \
          -keyout rsa/client.key \
          -out rsa/client.req \
          -sha256 \
          -batch \
          -subj "/CN=GLA client"

openssl rsa \
          -in rsa/client.key \
          -out rsa/client.rsa

# ecdsa
openssl ecparam -name prime256v1 -out ecdsa/nistp256.pem
openssl ecparam -name secp384r1 -out ecdsa/nistp384.pem

openssl req -nodes \
          -x509 \
          -newkey ec:ecdsa/nistp384.pem \
          -keyout ecdsa/ca.key \
          -out ecdsa/ca.cert \
          -sha256 \
          -batch \
          -days 3650 \
          -subj "/CN=GLA ECDSA CA"

openssl req -nodes \
          -newkey ec:ecdsa/nistp256.pem \
          -keyout ecdsa/inter.key \
          -out ecdsa/inter.req \
          -sha256 \
          -batch \
          -days 3000 \
          -subj "/CN=GLA ECDSA level 2 intermediate"

openssl req -nodes \
          -newkey ec:ecdsa/nistp256.pem \
          -keyout ecdsa/end.key \
          -out ecdsa/end.req \
          -sha256 \
          -batch \
          -days 2000 \
          -subj "/CN=quic-rust.com"

openssl req -nodes \
          -newkey ec:ecdsa/nistp384.pem \
          -keyout ecdsa/client.key \
          -out ecdsa/client.req \
          -sha256 \
          -batch \
          -days 2000 \
          -subj "/CN=GLA client"

for kt in rsa ecdsa ; do
  openssl x509 -req \
            -in $kt/inter.req \
            -out $kt/inter.cert \
            -CA $kt/ca.cert \
            -CAkey $kt/ca.key \
            -sha256 \
            -days 3650 \
            -set_serial 123 \
            -extensions v3_inter -extfile openssl.cnf

  openssl x509 -req \
            -in $kt/end.req \
            -out $kt/end.cert \
            -CA $kt/inter.cert \
            -CAkey $kt/inter.key \
            -sha256 \
            -days 2000 \
            -set_serial 456 \
            -extensions v3_end -extfile openssl.cnf

  openssl x509 -req \
            -in $kt/client.req \
            -out $kt/client.cert \
            -CA $kt/inter.cert \
            -CAkey $kt/inter.key \
            -sha256 \
            -days 2000 \
            -set_serial 789 \
            -extensions v3_client -extfile openssl.cnf

  cat $kt/inter.cert $kt/ca.cert > $kt/end.chain
  cat $kt/end.cert $kt/inter.cert $kt/ca.cert > $kt/end.fullchain

  cat $kt/inter.cert $kt/ca.cert > $kt/client.chain
  cat $kt/client.cert $kt/inter.cert $kt/ca.cert > $kt/client.fullchain

  openssl asn1parse -in $kt/ca.cert -out $kt/ca.der > /dev/null
done
