/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
)

// keyCmd represents the keytool command
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Generate a new private key",
	Long: `
Generate a new private key

Example:
  $ certools key -o private.key -t RSA -s 2048
	`,
	Run: runCreateKey,
}

func init() {
	rootCmd.AddCommand(keyCmd)

	keyCmd.Flags().StringP("output", "o", "", "Output file")
	keyCmd.Flags().StringP("type", "t", "RSA", "Key type (e.g. RSA, EC)")
	keyCmd.Flags().StringP("curve", "c", "P-256", "Curve (e.g. P-256, P-384, P-521)")
	keyCmd.Flags().IntP("size", "s", 256, "Key size")

}

func runCreateKey(cmd *cobra.Command, args []string) {
	fmt.Println("Generate Private Key")

	var kty, crv string
	var size int

	fmt.Print("Enter Key Type (e.g RSA): ")
	_, _ = fmt.Scan(&kty)
	fmt.Print("Enter Curve or type NONE if RSA (e.g P-256): ")
	_, _ = fmt.Scan(&crv)
	fmt.Print("Enter Size (e.g 256): ")
	_, _ = fmt.Scan(&size)

	priv, pub, err := generateKeyPair(kty, crv, size)
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}

	if outputFile := cmd.Flag("output").Value.String(); outputFile != "" {

		filepaths := strings.Split(outputFile, "/")
		// Create the directory if it doesn't exist. output file contain name of the file in the last index
		if len(filepaths) > 1 {
			if err := os.MkdirAll(strings.Join(filepaths[:len(filepaths)-1], "/"), 0755); err != nil {
				fmt.Println("Error creating directory:", err)
				return
			}
		}

		if err := os.WriteFile(outputFile, priv, 0600); err != nil {
			fmt.Println("Error writing private key to file:", err)
			return
		}

		fmt.Println("Private key written to:", outputFile)

		if err := os.WriteFile(outputFile+".pub", pub, 0644); err != nil {
			fmt.Println("Error writing public key to file:", err)
			return
		}

		fmt.Println("Public key written to:", outputFile+".pub")
	} else {
		fmt.Println("Private Key:")
		fmt.Println(string(priv))

		fmt.Println("Public Key:")
		fmt.Println(string(pub))
	}
}

func generateKeyPair(kty, crv string, size int) ([]byte, []byte, error) {
	// Generate a new key pair
	pub, priv, err := keyutil.GenerateKeyPair(kty, crv, size)
	if err != nil {
		return nil, nil, errors.Join(errors.New("error generating key pair"), err)
	}

	privBlock, err := pemutil.Serialize(priv)
	if err != nil {
		return nil, nil, errors.Join(errors.New("error serializing private key"), err)
	}

	pubBlock, err := pemutil.Serialize(pub)
	if err != nil {
		return nil, nil, errors.Join(errors.New("error serializing public key"), err)
	}

	privBytes := pem.EncodeToMemory(privBlock)
	pubBytes := pem.EncodeToMemory(pubBlock)

	return privBytes, pubBytes, nil
}
