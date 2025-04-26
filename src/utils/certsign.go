package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/lowRISC/opentitan-provisioning/src/pk11"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/se"
	"github.com/lowRISC/opentitan-provisioning/src/utils"
	"github.com/lowRISC/opentitan-provisioning/src/version/buildver"
)

var (
	hsmPW      = flag.String("hsm_pw", "", "Password for the HSM; required")
	hsmSOPath  = flag.String("hsm_so_path", "", "Path to the HSM PKCS#11 .so library; required")
	hsmSlot    = flag.Int("hsm_slot", -1, "Slot number of the HSM; required")
	caCertPath = flag.String("ca", "", "Path to the CA certificate")
	caKeyPath  = flag.String("ca_key", "", "Object label of the CA private key to use")
	csr        = flag.Bool("csr", false, "Generate a CSR instead of a self-signed certificate")
	keyPath    = flag.String("key", "", "Object label of the private key to use; required")
	rootCA     = flag.Bool("root_ca", false, "Generate a root CA certificate. Makes `ca_key` optional.")
	subject    = flag.String("subject", "", "Subject of the certificate in JSON format; required")
	validity   = flag.Duration("validity", 365*24*time.Hour, "Validity period of the certificate; required")
	version    = flag.Bool("version", false, "Print the version  information and exit")
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

func subjectToName() (pkix.Name, error) {
	if *subject == "" {
		return pkix.Name{}, fmt.Errorf("subject is required")
	}
	var subObj SubjectJSON
	if err := json.Unmarshal([]byte(*subject), &subObj); err != nil {
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

func buildCertTemplate(session *pk11.Session) (*x509.Certificate, error) {
	serialNumber, err := session.GenerateRandom(10)
	if err != nil {
		return nil, fmt.Errorf("could not generate serial number: %v", err)
	}

	// The serial number must be a positive integer, so we need to make sure
	// that the first byte is not 0x00.
	serialNumber[0] &= 0x7F
	if serialNumber[0] == 0 {
		serialNumber[0] = 1
	}
	certSN := new(big.Int).SetBytes(serialNumber)

	name, err := subjectToName()
	if err != nil {
		return nil, fmt.Errorf("could not convert subject to name: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          certSN,
		Subject:               name,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(*validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		IssuingCertificateURL: nil,
	}
	return template, nil
}

func signCert(session *pk11.Session, template *x509.Certificate) ([]byte, error) {
	if *caKeyPath == "" && !*rootCA {
		return nil, fmt.Errorf("ca_key is required if root_ca is not set")
	}
	if *keyPath == "" {
		return nil, fmt.Errorf("key is required")
	}

	keyObj, err := session.FindKeyByLabel(&pk11.ClassPrivateKey, *keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not find key object with label %q: %v", *keyPath, err)
	}

	caKeyObj := keyObj
	caTemplate := template
	if !*rootCA {
		caKeyObj, err = session.FindKeyByLabel(&pk11.ClassPrivateKey, *caKeyPath)
		if err != nil {
			return nil, fmt.Errorf("could not find CA key object with label %q: %v", *caKeyPath, err)
		}
		caTemplate, err = utils.LoadCertFromFile(*caCertPath)
		if err != nil {
			return nil, fmt.Errorf("could not load CA certificate from file %q: %v", *caCertPath, err)
		}
	}
	id, err := caKeyObj.UID()
	if err != nil {
		return nil, fmt.Errorf("could not get UID of CA key object: %v", err)
	}
	ca, err := session.FindPrivateKey(id)
	if err != nil {
		return nil, fmt.Errorf("could not find CA private key: %v", err)
	}
	caKey, err = ca.Signer()
	if err != nil {
		return nil, fmt.Errorf("could not get signer for CA key: %v", err)
	}

	id, err = keyObj.UID()
	if err != nil {
		return nil, fmt.Errorf("could not get UID of key object: %v", err)
	}
	key, err := session.FindPrivateKey()

	return certDER, nil
}

// initSession creates a new HSM instance with a single token session.
func initSession() (*se.HSM, error) {
	return se.NewHSM(se.HSMConfig{
		SOPath:      *hsmSOPath,
		SlotID:      *hsmSlot,
		HSMPassword: *hsmPW,
		NumSessions: 1,
	})
}

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Version: %s\n", buildver.Version)
		return
	}

	if *hsmSOPath == "" || *hsmSlot == -1 || *hsmPW == "" {
		flag.Usage()
		return
	}

	session, err := initSession()
	if err != nil {
		log.Fatalf("Error initializing HSM: %v", err)
	}
	defer session.Close()

	template, err := buildCertTemplate(session)
	if err != nil {
		log.Fatalf("Error building certificate template: %v\n", err)
	}

	certDER, err := signCert(session, template)
	if err != nil {
		log.Fatalf("Error signing certificate: %v\n", err)
	}

	fmt.Printf("Certificate generated successfully:\n%s\n", certDER)
}
