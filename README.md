# Notation release signing example

## Generate signing key
1. Use OpenSSL to generate a signing key with certificate
```sh
keyname=notation
subject="/C=US/ST=Redmond/L=Redmond/O=notation/CN=notation-local-signer"

openssl req  \
    -config <(printf "[req]\ndistinguished_name=subject\n[subject]\n") \
    -addext "basicConstraints=CA:false" -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=codeSigning" \
    -sha256 -subj "$subject" \
    -newkey ec:<(openssl ecparam -name secp256r1) \
    -nodes -keyout ${keyname}.key -x509 -out ${keyname}.crt \
    -days 365
```

2. Use notation local-signer plugin to encrypt the key. Follow the prompt to enter the password
```
notation-local-signer encrypt "./notationkey"
```

Then you can remove your $keynane.key to avoid the key leak.

## Set up release signing for Github
1. add your notationcrt file to your code repository, which will be used for the verifier to download
2. add a Github workflow secret to store the content of notationkey.enc file and export the value to env `LOCAL_SIGNER_SIGNING_KEY`
3. add a Github workflow secret to store your password and export the value to env `LOCAL_SIGNER_SIGNING_KEY_PASSWORD`
3. setup release signing workflow with notation
```
notation blob sign --id local-signer --plugin local-signer \
  --plugin-config certificate_bundle_path='./notation.crt'
```


## Verification
The Signature publisher should prepare the certificate downloading URL, certificate sha256 fingerprint, and the trusted identity and publish it on the trusted source to the downloader to verify your released assets with signature.

To get the certificate sha256 fingerprint, please run:
```
shasum -a 256 notation.crt | cut -d ' ' -f1
```
To get signing certificate trusted identity, please run:
```
echo "x509.subject: $(openssl x509 -in notation.crt -subject -noout | awk -F'subject=' '{print $2}')"
```

```sh
# verifier need type in the fields
SIGNATURE=<signature-path>
TARGET_FILE=<signed-target-file-path>

notation blob quick-verify \
  --certificate-url "https://raw.githubusercontent.com/JeyJeyGao/notation-local-signer/refs/tags/v1/notation.crt" \
  --trusted-identity "x509.subject: C = US, ST = Redmond, L = Redmond, O = notation, CN = notation-local-signer" \
  --signature $SIGNATURE \
  $TARGET_FILE
```
