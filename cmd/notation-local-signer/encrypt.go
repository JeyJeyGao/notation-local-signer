package main

import (
	"fmt"
	"os"

	"github.com/notaryproject/notation-core-go/x509"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func encryptCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt [path]",
		Short: "Encrypt a private key file",
		Long:  "Encrypt a private key file with a password and save it with .enc extension",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEncrypt(args[0])
		},
	}
}

func runEncrypt(path string) error {
	// Read private key file
	keyData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	// Verify it's a valid private key
	_, err = x509.ParsePrivateKeyPEM(keyData)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	// Prompt for password
	fmt.Print("Enter password to encrypt the key: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()

	// Confirm password
	fmt.Print("Confirm password: ")
	confirmPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read confirmation password: %w", err)
	}
	fmt.Println()

	if string(password) != string(confirmPassword) {
		return fmt.Errorf("passwords do not match")
	}

	// Encrypt the key
	encryptedData, err := encrypted.Encrypt(keyData, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Generate output file name
	outputPath := path + ".enc"

	// Write encrypted key to file
	err = os.WriteFile(outputPath, encryptedData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write encrypted key: %w", err)
	}

	fmt.Printf("\nPrivate key encrypted successfully and saved to %s\n", outputPath)

	return nil
}
