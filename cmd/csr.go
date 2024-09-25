/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.step.sm/crypto/pemutil"
)

// csrCmd represents the csr command
var csrCmd = &cobra.Command{
	Use:   "csr",
	Short: "Generate a new certificate signing request",
	Long: `
Generate a new certificate signing request

Example:
  $ certools csr -o csr.pem -k private.key
	`,
	Run: runCreateCsr,
}

func init() {
	rootCmd.AddCommand(csrCmd)

	csrCmd.Flags().StringP("output", "o", "", "Output file")
	csrCmd.Flags().StringP("privatekey", "k", "", "Private key file")
}

func runCreateCsr(cmd *cobra.Command, args []string) {

	var (
		commonname, country, organization, ou, email string
		DNs                                          []string
	)
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Common Name: ")
	input, _ := reader.ReadString('\n')
	commonname = strings.TrimSuffix(input, "\n")
	fmt.Print("Enter Country: ")
	input, _ = reader.ReadString('\n')
	country = strings.TrimSuffix(input, "\n")
	fmt.Print("Enter Organization: ")
	input, _ = reader.ReadString('\n')
	organization = strings.TrimSuffix(input, "\n")
	fmt.Print("Enter Organizational Unit: ")
	input, _ = reader.ReadString('\n')
	ou = strings.TrimSuffix(input, "\n")
	fmt.Print("Enter DNs: ")
	input, _ = reader.ReadString('\n')
	DNs = strings.Split(strings.TrimSuffix(input, "\n"), ",")
	fmt.Print("Enter Email: ")
	input, _ = reader.ReadString('\n')
	email = strings.TrimSuffix(input, "\n")

	privfile, err := cmd.Flags().GetString("privatekey")
	if err != nil {
		fmt.Println("Error reading private key file:", err)
		return
	}

	signer, err := generateSigner(privfile)
	if err != nil {
		fmt.Println("Error generating signer:", err)
		return
	}

	asn1Data, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         commonname,
			Country:            []string{country},
			Organization:       []string{organization},
			OrganizationalUnit: []string{ou},
		},
		DNSNames:       DNs,
		EmailAddresses: []string{email},
	}, signer)
	if err != nil {
		fmt.Println("Error creating certificate request:", err)
		return
	}

	csr, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		fmt.Println("Error parsing certificate request:", err)
		return
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})

	if outputFile := cmd.Flag("output").Value.String(); outputFile != "" {
		filepaths := strings.Split(outputFile, "/")
		// Create the directory if it doesn't exist. output file contain name of the file in the last index
		if len(filepaths) > 1 {
			if err := os.MkdirAll(strings.Join(filepaths[:len(filepaths)-1], "/"), 0755); err != nil {
				fmt.Println("Error creating directory:", err)
				return
			}
		}

		if err := os.WriteFile(outputFile, csrPEM, 0600); err != nil {
			fmt.Println("Error writing csr to file:", err)
			return
		}

		fmt.Println("CSR written to:", outputFile)
	} else {
		fmt.Println("Certificate Request:")
		fmt.Println(string(csrPEM))
	}
}

func generateSigner(privfile string) (crypto.Signer, error) {
	priv, err := pemutil.Read(privfile)
	if err != nil {
		return nil, errors.Join(errors.New("error reading private key"), err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key is not a signer")
	}

	return signer, nil

}
