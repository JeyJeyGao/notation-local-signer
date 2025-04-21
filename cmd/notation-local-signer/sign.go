package main

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/spf13/cobra"
	"github.com/veraison/go-cose"
)

func signCommand() *cobra.Command {
	return &cobra.Command{
		Use:  string(proto.CommandGenerateSignature),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSign()
		},
	}
}

func runSign() error {
	// decode request
	var req proto.GenerateSignatureRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to unmarshal request input: %w", err),
		}
	}

	// sign
	resp, err := sign(&req)
	if err != nil {
		return err
	}

	// encode response
	return json.NewEncoder(os.Stdout).Encode(resp)
}

func sign(req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error) {
	certBundle, ok := req.PluginConfig["certificate_bundle_path"]
	if !ok {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("no certificate bundle path found"),
		}
	}

	// read certificate
	certs, err := x509.ReadCertificateFile(certBundle)
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to read certificate file: %w", err),
		}
	}
	if len(certs) == 0 {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("no certificate found"),
		}
	}

	encryptedKey := os.Getenv("LOCAL_SIGNER_SIGNING_KEY")
	if encryptedKey == "" {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("environment variable ENCRYPTED_PRIVATE_KEY not set"),
		}
	}

	password := os.Getenv("LOCAL_SIGNER_SIGNING_KEY_PASSWORD")
	if password == "" {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("no password specified for the encrypted private key"),
		}
	}

	keyValue, err := encrypted.Decrypt([]byte(encryptedKey), []byte(password))
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to decrypt private key: %w", err),
		}
	}

	key, err := x509.ParsePrivateKeyPEM(keyValue)
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to parse private key: %w", err),
		}
	}

	// sign
	keySpec, err := signature.ExtractKeySpec(certs[0])
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to extract key spec: %w", err),
		}
	}
	alg, err := getSignatureAlgorithmFromKeySpec(keySpec)
	if err != nil {
		return nil, proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to get signature algorithm: %w", err),
		}
	}
	cryptoSigner, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a crypto.Signer")
	}
	signer, err := cose.NewSigner(alg, cryptoSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}
	sig, err := signer.Sign(rand.Reader, req.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// generate response
	signingAlgorithm, err := proto.EncodeSigningAlgorithm(keySpec.SignatureAlgorithm())
	if err != nil {
		return nil, fmt.Errorf("failed to encode signing algorithm: %w", err)
	}
	certChain := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		certChain = append(certChain, cert.Raw)
	}
	return &proto.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        sig,
		SigningAlgorithm: string(signingAlgorithm),
		CertificateChain: certChain,
	}, nil
}

func getSignatureAlgorithmFromKeySpec(keySpec signature.KeySpec) (cose.Algorithm, error) {
	switch keySpec.Type {
	case signature.KeyTypeRSA:
		switch keySpec.Size {
		case 2048:
			return cose.AlgorithmPS256, nil
		case 3072:
			return cose.AlgorithmPS384, nil
		case 4096:
			return cose.AlgorithmPS512, nil
		default:
			return 0, &signature.UnsupportedSigningKeyError{Msg: fmt.Sprintf("RSA: key size %d not supported", keySpec.Size)}
		}
	case signature.KeyTypeEC:
		switch keySpec.Size {
		case 256:
			return cose.AlgorithmES256, nil
		case 384:
			return cose.AlgorithmES384, nil
		case 521:
			return cose.AlgorithmES512, nil
		default:
			return 0, &signature.UnsupportedSigningKeyError{Msg: fmt.Sprintf("EC: key size %d not supported", keySpec.Size)}
		}
	default:
		return 0, &signature.UnsupportedSigningKeyError{Msg: "key type not supported"}
	}
}
