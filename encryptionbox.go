package encryptionbox

import (
	"bytes"
	"crypto/rand"
)

type EncryptionBox struct {
	RSA rsaMethods
	AES aesMethods
}

func (eb EncryptionBox) KeyGenerate16Bytes() (key []byte, err error) {
	key = make([]byte, 16)
	_, err = rand.Read(key)
	return
}

func (eb EncryptionBox) KeyGenerate24Bytes() (key []byte, err error) {
	key = make([]byte, 24)
	_, err = rand.Read(key)
	return
}

func (eb EncryptionBox) KeyGenerate32Bytes() (key []byte, err error) {
	key = make([]byte, 32)
	_, err = rand.Read(key)
	return
}

func (eb EncryptionBox) PadDataPkcs5(data []byte, blockSize int) (paddedData []byte) {
	padding := blockSize - len(data)%blockSize
	paddedData = append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)
	return
}

func (eb EncryptionBox) TrimDataPkcs5(paddedData []byte) (data []byte) {
	padding := paddedData[len(paddedData)-1]
	data = paddedData[:len(paddedData)-int(padding)]
	return
}
