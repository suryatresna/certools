/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x509util"
)

// certCmd represents the cert command
var certCmd = &cobra.Command{
	Use:   "certificate",
	Short: "Generate a new certificate",
	Long: `
	Generate a new certificate using the provided private key
	`,
	Run: handleCreateCertificate,
}

const (
	// Default durations
	defaultLeafValidity         = 24 * time.Hour
	defaultSelfSignedValidity   = 24 * time.Hour
	defaultIntermediateValidity = time.Hour * 24 * 365 * 10
	defaultRootValidity         = time.Hour * 24 * 365 * 10
	defaultTemplatevalidity     = 24 * time.Hour
)

func init() {
	rootCmd.AddCommand(certCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	certCmd.Flags().StringP("csr", "r", "", "Certificate request file")
	certCmd.Flags().StringP("key", "k", "", "Private key file")
	certCmd.Flags().StringP("profile", "p", "", "Certificate profile. ex: root, intermediate, leaf, self-signed")
	certCmd.Flags().StringP("output", "o", "", "Output file")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// certCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func handleCreateCertificate(cmd *cobra.Command, args []string) {
	reader := bufio.NewReader(os.Stdin)

	// parse and check csr signature
	csrFile := cmd.Flag("csr").Value.String()
	csr, err := pemutil.ReadCertificateRequest(csrFile)
	if err != nil {
		fmt.Println("Error reading certificate request:", err)
		return
	}
	if err = csr.CheckSignature(); err != nil {
		fmt.Println("Error validating certificate request:", err)
		return
	}

	profile := cmd.Flag("profile").Value.String()
	tmpl, validity, err := createTemplateCertificate(profile)
	if err != nil {
		fmt.Println("Error creating certificate template:", err)
		return
	}

	// get signer key
	privfile := cmd.Flag("key").Value.String()
	signer, err := generateSigner(privfile, reader)
	if err != nil {
		fmt.Println("Error generating signer:", err)
		return
	}

	// create certificate template
	templateData := x509util.CreateTemplateData(csr.Subject.CommonName, csr.DNSNames)

	certCsr, err := x509util.NewCertificate(csr, x509util.WithTemplate(tmpl, templateData))
	if err != nil {
		fmt.Println("Error creating certificate for csr:", err)
		return
	}
	certTemplate := certCsr.GetCertificate()

	// set validity
	if certTemplate.NotBefore.IsZero() {
		certTemplate.NotBefore = time.Now()
	}
	if certTemplate.NotAfter.IsZero() {
		certTemplate.NotAfter = certTemplate.NotBefore.Add(validity)
	}
	// Check that the certificate is not already expired
	if certTemplate.NotBefore.After(certTemplate.NotAfter) {
		fmt.Println("Error: certificate is already expired")
		return
	}

	// set serial number and subject key id
	if certTemplate.SerialNumber == nil {
		if certTemplate.SerialNumber, err = generateSerialNumber(); err != nil {
			fmt.Println("Error generating serial number:", err)
			return
		}
	}
	if certTemplate.SubjectKeyId == nil {
		if certTemplate.SubjectKeyId, err = generateSubjectKeyID(csr.PublicKey); err != nil {
			fmt.Println("Error generating subject key id:", err)
			return
		}
	}

	// create certificate
	cert, err := createCertificate(certTemplate, certTemplate, csr.PublicKey, signer.(crypto.Signer))
	if err != nil {
		fmt.Println("Error creating certificate:", err)
		return
	}

	// write certificate to file
	block, err := pemutil.Serialize(cert)
	if err != nil {
		fmt.Println("Error serializing certificate:", err)
		return
	}

	pubBytes := pem.EncodeToMemory(block)

	if outputFile := cmd.Flag("output").Value.String(); outputFile != "" {
		filepaths := strings.Split(outputFile, "/")
		// Create the directory if it doesn't exist. output file contain name of the file in the last index
		if len(filepaths) > 1 {
			if err := os.MkdirAll(strings.Join(filepaths[:len(filepaths)-1], "/"), 0755); err != nil {
				fmt.Println("Error creating directory:", err)
				return
			}
		}

		if err := os.WriteFile(outputFile, pubBytes, 0600); err != nil {
			fmt.Println("Error writing x509 cert to file:", err)
			return
		}

		fmt.Println("x509 Cert written to:", outputFile)
	} else {
		fmt.Println("Certificate:")
		fmt.Println(string(pubBytes))
	}

}

func createTemplateCertificate(profile string) (string, time.Duration, error) {
	var (
		defaultValidity time.Duration
		template        string
	)

	switch profile {
	case "leaf":
		template = x509util.DefaultLeafTemplate
		defaultValidity = defaultLeafValidity
	case "intermediate":
		template = x509util.DefaultIntermediateTemplate
		defaultValidity = defaultIntermediateValidity
	case "root":
		template = x509util.DefaultRootTemplate
		defaultValidity = defaultRootValidity
	case "self-signed":
		template = x509util.DefaultLeafTemplate
		defaultValidity = defaultSelfSignedValidity
	default:
		return "", defaultValidity, errors.Errorf("profile %s not supported", profile)
	}

	return template, defaultValidity, nil
}

// createCertificate sets the SignatureAlgorithm of the template if necessary
// and calls x509util.CreateCertificate.
func createCertificate(template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	asn1Data, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		return nil, errors.Wrap(err, "error creating certificate")
	}
	cert, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing certificate")
	}
	return cert, nil
}

// generateSerialNumber returns a random serial number.
func generateSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, errors.Wrap(err, "error generating serial number")
	}
	return sn, nil
}

// subjectPublicKeyInfo is a PKIX public key structure defined in RFC 5280.
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// generateSubjectKeyID generates the key identifier according the the RFC 5280
// section 4.2.1.2.
//
// The keyIdentifier is composed of the 160-bit SHA-1 hash of the value of the
// BIT STRING subjectPublicKey (excluding the tag, length, and number of unused
// bits).
func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling public key")
	}
	var info subjectPublicKeyInfo
	if _, err = asn1.Unmarshal(b, &info); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling public key")
	}
	//nolint:gosec // SubjectKeyIdentifier by RFC 5280
	hash := sha1.Sum(info.SubjectPublicKey.Bytes)
	return hash[:], nil
}
