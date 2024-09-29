/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto"
	"encoding/pem"
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
	keyCmd.Flags().BoolP("insecure", "w", false, "Generate a private key without password")

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

	pub, priv, err := keyutil.GenerateKeyPair(kty, crv, size)
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}

	var privBytes []byte
	if insecure := cmd.Flag("insecure").Value.String(); insecure == "true" {
		privBlock, err := pemutil.Serialize(priv)
		if err != nil {
			fmt.Println("Error serializing private key:", err)
			return
		}
		privBytes = pem.EncodeToMemory(privBlock)
	} else {
		fmt.Print("Enter Password: ")
		var pass string
		_, _ = fmt.Scan(&pass)

		privBlock, err := setPassword(priv, pass)
		if err != nil {
			fmt.Println("Error serializing private key:", err)
			return
		}
		privBytes = pem.EncodeToMemory(privBlock)
	}

	pubBlock, err := pemutil.Serialize(pub)
	if err != nil {
		fmt.Println("Error serializing public key:", err)
		return
	}

	pubBytes := pem.EncodeToMemory(pubBlock)

	if outputFile := cmd.Flag("output").Value.String(); outputFile != "" {

		filepaths := strings.Split(outputFile, "/")
		// Create the directory if it doesn't exist. output file contain name of the file in the last index
		if len(filepaths) > 1 {
			if err := os.MkdirAll(strings.Join(filepaths[:len(filepaths)-1], "/"), 0755); err != nil {
				fmt.Println("Error creating directory:", err)
				return
			}
		}

		if err := os.WriteFile(outputFile, privBytes, 0600); err != nil {
			fmt.Println("Error writing private key to file:", err)
			return
		}

		fmt.Println("Private key written to:", outputFile)

		if err := os.WriteFile(outputFile+".pub", pubBytes, 0644); err != nil {
			fmt.Println("Error writing public key to file:", err)
			return
		}

		fmt.Println("Public key written to:", outputFile+".pub")
	} else {
		fmt.Println("Private Key:")
		fmt.Println(string(privBytes))

		fmt.Println("Public Key:")
		fmt.Println(string(pubBytes))
	}
}

func setPassword(priv crypto.PrivateKey, pass string) (*pem.Block, error) {
	var (
		err      error
		pemBlock *pem.Block
	)
	if pass != "" {
		pemBlock, err = pemutil.Serialize(priv, pemutil.WithPassword([]byte(pass)))
	}
	return pemBlock, err
}
