package azblob

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/rubrikinc/azure-pipeline-go/pipeline"
)

const (
	encryptionAlgorithm = "AES256"
)

// CustomerEncryptionKey is AES265 encryption key for azure customer provided
// encryption key feature. If it is nil, it means that customer encryption keys
// will not be used.
type CustomerEncryptionKey []byte

// InvalidAES256KeyLength is returned when the provided key has an invalid
// length.
type InvalidAES256KeyLength error

func newInvalidAES256KeyLength(length int) InvalidAES256KeyLength {
	return fmt.Errorf("Invalid key length, must be 32 bytes: %d", length)
}

// blobEncryptionHeaders includes the http headers needed for using Customer
// provided encryption.
type blobEncryptionHeaders struct {
	key     string
	keySha2 string
}

// newBlobEncryptionHeader creates a new blobEncryptionHeaders. A nil key is
// is a valid input and indicates that this type of encryption won't be used.
// A non-nil key must have length 32.
func newBlobEncryptionHeader(key []byte) (*blobEncryptionHeaders, error) {
	if key == nil {
		return nil, nil
	}
	// sha2 requires 32 bytes encryption key.
	if len(key) != 32 {
		return nil, newInvalidAES256KeyLength(len(key))
	}
	eKey := make([]byte, base64.StdEncoding.EncodedLen(len(key)))
	base64.StdEncoding.Encode(eKey, key)
	sKeyHash := sha256.Sum256(key)
	sKey := make([]byte, base64.StdEncoding.EncodedLen(len(sKeyHash)))
	base64.StdEncoding.Encode(sKey, sKeyHash[:])
	return &blobEncryptionHeaders{
		key:     string(eKey),
		keySha2: string(sKey),
	}, nil
}

// setEncryptionHeaders augments a http request with the encryption headers, if
// necessary.
func setEncryptionHeaders(
	req pipeline.Request,
	enc *blobEncryptionHeaders,
) pipeline.Request {
	if enc != nil {
		req.Header.Set("x-ms-encryption-key", enc.key)
		req.Header.Set("x-ms-encryption-key-sha256", enc.keySha2)
		req.Header.Set("x-ms-encryption-algorithm", encryptionAlgorithm)
	}
	return req
}
