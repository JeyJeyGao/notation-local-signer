# Notation Release Signing Example

## Generate Signing Key
1. Use OpenSSL to generate a signing key with certificate:
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

2. Use notation local-signer plugin to encrypt the key. Follow the prompt to enter the password:
```sh
notation-local-signer encrypt "${keyname}.key"
```

After encryption, you should delete the unencrypted `${keyname}.key` file to prevent accidental key exposure.

## Set Up Release Signing for GitHub
1. Add your certificate file (notation.crt) to your code repository, which will be used by verifiers to download.
2. Add a GitHub workflow secret to store the content of the encrypted key file (notation.key.enc) and export the value to the environment variable `LOCAL_SIGNER_SIGNING_KEY`.
3. Add a GitHub workflow secret to store your password and export the value to the environment variable `LOCAL_SIGNER_SIGNING_KEY_PASSWORD`.
4. Set up a release signing workflow with notation:
```sh
notation blob sign --id local-signer --plugin local-signer \
  --plugin-config certificate_bundle_path='./notation.crt'
```


## Verification
The signature publisher should prepare the certificate download URL, certificate SHA256 fingerprint, and the trusted identity and publish this information on a trusted source for downloaders to verify released assets with signatures.

To get the certificate SHA256 fingerprint, please run:
```bash
shasum -a 256 notation.crt | cut -d ' ' -f1
```

To get the signing certificate's trusted identity, please run:
```bash
echo "x509.subject: $(openssl x509 -in notation.crt -subject -noout | awk -F'subject=' '{print $2}')"
```

For verifiers to validate a signature, they should use:
```bash
# Replace these variables with actual values
SIGNATURE=<signature-path>
TARGET_FILE=<signed-target-file-path>

notation blob quick-verify \
  --certificate-url "https://raw.githubusercontent.com/JeyJeyGao/notation-local-signer/refs/tags/v1/notation.crt" \
  --sha256sum "b3f47ce158f3caf4af84f016d41daeed9820494a6ff86b9e07ba471fc8fd977e" \
  --trusted-identity "x509.subject: C = US, ST = Redmond, L = Redmond, O = notation, CN = notation-local-signer" \
  --signature $SIGNATURE \
  $TARGET_FILE
```
