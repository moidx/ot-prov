package ate

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Test data mirroring ate_perso_blob_test.cc
var (
	testDeviceID = &DeviceIDBytes{
		Raw: [kDeviceIDSize]byte{
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
	}
	testSignature = &EndorseCertSignature{
		Raw: [kWasHmacSignatureSize]byte{
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
	}
	testTbsCert = EndorseCertRequest{
		KeyLabel: "testkey1",
		Tbs:      bytes.Repeat([]byte{0x44}, 128),
	}
	testCert = EndorseCertResponse{
		KeyLabel: "testkey1",
		Cert:     bytes.Repeat([]byte{0x33}, 128),
	}
)

// createTestPersoBlob creates a valid perso blob for testing UnpackPersoBlob.
// It mirrors the C++ test's CreateTestPersoBlob function.
func createTestPersoBlob() ([]byte, error) {
	var buf bytes.Buffer

	// 1. Device ID object
	objSize := uint16(sizeOfObjectHeader + len(testDeviceID.Raw))
	header := SetObjectHeaderFields(objSize, PersoObjectTypeDeviceId)
	if err := binary.Write(&buf, binary.BigEndian, header); err != nil {
		return nil, err
	}
	if _, err := buf.Write(testDeviceID.Raw[:]); err != nil {
		return nil, err
	}

	// 2. Signature object
	objSize = uint16(sizeOfObjectHeader + len(testSignature.Raw))
	header = SetObjectHeaderFields(objSize, PersoObjectTypeWasTbsHmac)
	if err := binary.Write(&buf, binary.BigEndian, header); err != nil {
		return nil, err
	}
	if _, err := buf.Write(testSignature.Raw[:]); err != nil {
		return nil, err
	}

	// 3. TBS certificate object
	keyLabelBytes := []byte(testTbsCert.KeyLabel)
	certEntrySize := uint16(sizeOfCertHeader + len(keyLabelBytes) + len(testTbsCert.Tbs))
	objSize = uint16(sizeOfObjectHeader) + certEntrySize
	header = SetObjectHeaderFields(objSize, PersoObjectTypeX509Tbs)
	if err := binary.Write(&buf, binary.BigEndian, header); err != nil {
		return nil, err
	}

	certHeader := SetCertHeaderFields(certEntrySize, uint16(len(keyLabelBytes)))
	if err := binary.Write(&buf, binary.BigEndian, certHeader); err != nil {
		return nil, err
	}
	if _, err := buf.Write(keyLabelBytes); err != nil {
		return nil, err
	}
	if _, err := buf.Write(testTbsCert.Tbs); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func TestUnpackPersoBlobSuccess(t *testing.T) {
	blobBytes, err := createTestPersoBlob()
	if err != nil {
		t.Fatalf("createTestPersoBlob() failed: %v", err)
	}

	unpacked, err := UnpackPersoBlob(blobBytes)
	if err != nil {
		t.Fatalf("UnpackPersoBlob() failed: %v", err)
	}

	if diff := cmp.Diff(testDeviceID, unpacked.DeviceID); diff != "" {
		t.Errorf("Unpacked DeviceID mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(testSignature, unpacked.Signature); diff != "" {
		t.Errorf("Unpacked Signature mismatch (-want +got):\n%s", diff)
	}

	if got, want := len(unpacked.X509TbsCerts), 1; got != want {
		t.Fatalf("got %d TBS certs, want %d", got, want)
	}
	if diff := cmp.Diff(testTbsCert, unpacked.X509TbsCerts[0]); diff != "" {
		t.Errorf("Unpacked TBS Cert mismatch (-want +got):\n%s", diff)
	}

	if got, want := len(unpacked.X509Certs), 0; got != want {
		t.Errorf("got %d X509 certs, want %d", got, want)
	}
	if got, want := len(unpacked.Seeds), 0; got != want {
		t.Errorf("got %d seeds, want %d", got, want)
	}
}

func TestUnpackPersoBlobErrors(t *testing.T) {
	// Corrupt blob by removing the signature object, which is required.
	blobNoSig, _ := createTestPersoBlob()
	// signature object starts at offset 34 (2+32 for devid) and has size 34 (2+32).
	blobNoSig = append(blobNoSig[:34], blobNoSig[34+34:]...)

	// Corrupt blob by removing the TBS cert object, which is required.
	blobNoTbs, _ := createTestPersoBlob()
	// tbs cert object starts at offset 68 (34+34)
	blobNoTbs = blobNoTbs[:68]

	// Corrupt blob by removing the device ID object, which is required.
	blobNoDevID, _ := createTestPersoBlob()
	blobNoDevID = blobNoDevID[34:]

	// Corrupt blob with a zero device ID
	blobZeroDevID, _ := createTestPersoBlob()
	for i := 2; i < 34; i++ { // start at 2 to skip header
		blobZeroDevID[i] = 0
	}

	testCases := []struct {
		name      string
		blob      []byte
		expectErr string
	}{
		{
			name:      "nil blob",
			blob:      nil,
			expectErr: "invalid personalization blob: empty",
		},
		{
			name:      "empty blob",
			blob:      []byte{},
			expectErr: "invalid personalization blob: empty",
		},
		{
			name:      "blob too large",
			blob:      make([]byte, kPersoBlobMaxSize+1),
			expectErr: "blob size 8193 exceeds max 8192",
		},
		{
			name:      "incomplete header",
			blob:      []byte{0x01},
			expectErr: "remaining buffer too small for object header",
		},
		{
			name: "object size exceeds buffer",
			// Header says size is 10, but we only have 2 bytes
			blob:      []byte{0x00, 0x0a},
			expectErr: "object size 10 exceeds remaining buffer 2",
		},
		{
			name:      "missing signature",
			blob:      blobNoSig,
			expectErr: "no WAS TBS HMAC found in the blob",
		},
		{
			name:      "missing tbs cert",
			blob:      blobNoTbs,
			expectErr: "no TBS certificates found in the blob",
		},
		{
			name:      "missing device id",
			blob:      blobNoDevID,
			expectErr: "no Device ID found in the blob",
		},
		{
			name:      "zero device id",
			blob:      blobZeroDevID,
			expectErr: "device ID is empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnpackPersoBlob(tc.blob)
			if err == nil {
				t.Errorf("UnpackPersoBlob() succeeded, want error containing %q", tc.expectErr)
			} else if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("UnpackPersoBlob() returned error %q, want error containing %q", err, tc.expectErr)
			}
		})
	}
}
