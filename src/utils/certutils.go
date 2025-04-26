package certutils

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

var (
	oidExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
)

type SubjectJSON struct {
	Country            []string `json:"C,omitempty"`
	Organization       []string `json:"O,omitempty"`
	OrganizationalUnit []string `json:"OU,omitempty"`
	Locality           []string `json:"L,omitempty"`
	Province           []string `json:"ST,omitempty"`
	StreetAddress      []string `json:"Street,omitempty"`
	PostalCode         []string `json:"PostalCode,omitempty"`
	SerialNumber       string   `json:"SerialNumber,omitempty"`
	CommonName         string   `json:"CN,omitempty"`
}

func SubjectToName(subject string) (pkix.Name, error) {
	if subject == "" {
		return pkix.Name{}, fmt.Errorf("subject is required")
	}
	var subObj SubjectJSON
	if err := json.Unmarshal([]byte(subject), &subObj); err != nil {
		return pkix.Name{}, fmt.Errorf("could not unmarshal subject JSON: %v", err)
	}
	return pkix.Name{
		Country:            subObj.Country,
		Organization:       subObj.Organization,
		OrganizationalUnit: subObj.OrganizationalUnit,
		Locality:           subObj.Locality,
		Province:           subObj.Province,
		StreetAddress:      subObj.StreetAddress,
		PostalCode:         subObj.PostalCode,
		SerialNumber:       subObj.SerialNumber,
		CommonName:         subObj.CommonName,
	}, nil
}

// LoadCertFromFile reads a certificate from a file and parses it into an
// x509.Certificate object.
// If the file does not exist or cannot be read, it returns an error.
func LoadCertFromFile(filename string) (*x509.Certificate, error) {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read certificate file, error: %v", err)
	}

	block, _ := pem.Decode(fileBytes)
	if block != nil {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("unable to parse certificate in PEM format, error: %v", err)
			}
			return cert, nil
		}
	}

	cert, err := x509.ParseCertificate(fileBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate in DER format, error: %v", err)
	}
	return cert, nil
}
