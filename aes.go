package encryptionbox

import (
	"crypto/aes"
	"crypto/cipher"
)

type aesMethods struct {
}

func (a aesMethods) EncryptCBCPKCS5Padding(key, iv, data []byte) (encryptedData []byte, err error) {
	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}
	cbc := cipher.NewCBCEncrypter(block, iv)
	data = EncryptionBox{}.PadDataPKCS5(data, block.BlockSize())
	cbc.CryptBlocks(data, data)
	encryptedData = data
	return
}

func (a aesMethods) EncryptCBCPKCS5PaddingIVKey16Bytes(data []byte) (key, iv []byte, encryptedData []byte, err error) {
	key, err = EncryptionBox{}.KeyGenerate16Bytes()
	if err != nil {
		return
	}
	iv, err = EncryptionBox{}.KeyGenerate16Bytes()
	if err != nil {
		return
	}
	encryptedData, err = a.EncryptCBCPKCS5Padding(key, iv, data)
	return
}

func (a aesMethods) EncryptCBCPKCS5PaddingIVKey24Bytes(data []byte) (key, iv []byte, encryptedData []byte, err error) {
	key, err = EncryptionBox{}.KeyGenerate24Bytes()
	if err != nil {
		return
	}
	iv, err = EncryptionBox{}.KeyGenerate16Bytes()
	if err != nil {
		return
	}
	encryptedData, err = a.EncryptCBCPKCS5Padding(key, iv, data)
	return
}

func (a aesMethods) EncryptCBCPKCS5PaddingIVKey32Bytes(data []byte) (key, iv []byte, encryptedData []byte, err error) {
	key, err = EncryptionBox{}.KeyGenerate32Bytes()
	if err != nil {
		return
	}
	iv, err = EncryptionBox{}.KeyGenerate16Bytes()
	if err != nil {
		return
	}
	encryptedData, err = a.EncryptCBCPKCS5Padding(key, iv, data)
	return
}

func (a aesMethods) DecryptCBCPKCS5Padding(key, iv, encryptedData []byte) (decryptedData []byte, err error) {
	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	decryptedData = make([]byte, len(encryptedData))
	cbc.CryptBlocks(decryptedData, encryptedData)
	decryptedData = EncryptionBox{}.TrimDataPKCS5(decryptedData)
	return
}
