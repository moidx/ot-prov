package main

import (
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/lowRISC/opentitan-provisioning/src/pk11"
	"github.com/lowRISC/opentitan-provisioning/src/spm/services/se"
	"github.com/lowRISC/opentitan-provisioning/src/utils/certutils"
	"github.com/lowRISC/opentitan-provisioning/src/version/buildver"
)

var (
	hsmPW      = flag.String("hsm_pw", "", "Password for the HSM; required")
	hsmSOPath  = flag.String("hsm_so_path", "", "Path to the HSM PKCS#11 .so library; required")
	hsmSlot    = flag.Int("hsm_slot", -1, "Slot number of the HSM; required")
	keyPath    = flag.String("key", "", "Object label of the private key to use; required")
	subject    = flag.String("subject", "", "Subject of the certificate in JSON format; required")
	outputPath = flag.String("output", "", "Path to save the generated certificate; required")
	version    = flag.Bool("version", false, "Print the version  information and exit")
)

func buildCSR(session *pk11.Session) (*x509.CertificateRequest, error) {
	name, err := certutils.SubjectToName(*subject)
	if err != nil {
		return nil, fmt.Errorf("could not convert subject to name: %v", err)
	}
	csr := &x509.CertificateRequest{
		Subject:            name,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	return csr, nil
}

func signCSR(session *pk11.Session, template *x509.CertificateRequest) ([]byte, error) {
	if *keyPath == "" {
		return nil, fmt.Errorf("key is required")
	}
	keyObj, err := session.FindKeyByLabel(pk11.ClassPrivateKey, *keyPath)
	if err != nil {
		return nil, fmt.Errorf("could not find key object with label %q: %v", *keyPath, err)
	}

	id, err := keyObj.UID()
	if err != nil {
		return nil, fmt.Errorf("could not get UID of key object: %v", err)
	}
	ca, err := session.FindPrivateKey(id)
	if err != nil {
		return nil, fmt.Errorf("could not find private key: %v", err)
	}
	key, err := ca.Signer()
	if err != nil {
		return nil, fmt.Errorf("could not get signer for private key: %v", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("could not create CSR: %v", err)
	}
	return csrDER, nil
}

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Version: %s\n", buildver.FormattedStr())
		return
	}

	if *hsmSOPath == "" || *hsmSlot == -1 || *hsmPW == "" {
		flag.Usage()
		return
	}

	hsm, err := se.NewHSM(se.HSMConfig{
		SOPath:      *hsmSOPath,
		SlotID:      *hsmSlot,
		HSMPassword: *hsmPW,
		NumSessions: 1,
	})
	if err != nil {
		log.Fatalf("Error initializing HSM: %v", err)
	}

	certDER := []byte{}
	if err = hsm.ExecuteCmd(func(session *pk11.Session) error {
		template, err := buildCSR(session)
		if err != nil {
			return fmt.Errorf("Error building CSR: %v", err)
		}
		certDER, err = signCSR(session, template)
		if err != nil {
			return fmt.Errorf("Error signing CSR: %v", err)
		}
		return nil
	}); err != nil {
		log.Fatalf("Error executing CSR generation command: %v", err)
	}

	if *outputPath != "" {
		if err := os.WriteFile(*outputPath, certDER, 0644); err != nil {
			log.Fatalf("Error writing CSR to file %q: %v", *outputPath, err)
		}
		log.Printf("CSR written to %q\n", *outputPath)
	} else {
		log.Printf("CSR not written to file, output path is empty\n")
	}
}
