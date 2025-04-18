#!/bin/bash
name=notation
subject="/C=CN/ST=Shanghai/L=Shanghai/O=shizhMSFT/CN=notation-local-signer"
openssl req  \
    -config <(printf "[req]\ndistinguished_name=subject\n[subject]\n") \
    -addext "basicConstraints=CA:false" -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=codeSigning" \
    -sha256 -subj "$subject" \
    -newkey ec:<(openssl ecparam -name secp256r1) \
    -nodes -keyout ${name}.key -x509 -out ${name}.crt \
    -days 365
