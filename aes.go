package encryptionbox

import (
	"crypto/aes"
	"crypto/cipher"
)

type aesMethods struct {
}

func (a aesMethods) EncryptCbcPkcs5WithPadding(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)

	data = EncryptionBox{}.PadDataPkcs5(data, block.BlockSize())

	cbc.CryptBlocks(data, data)

	return data, nil
}

func (a aesMethods) EncryptCbcPkcs5RandomIvWithPadding(key, data []byte) (encryptedData, iv []byte, err error) {
	var block cipher.Block

	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	iv, err = EncryptionBox{}.KeyGenerate16Bytes()
	if err != nil {
		return nil, nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)

	data = EncryptionBox{}.PadDataPkcs5(data, block.BlockSize())

	cbc.CryptBlocks(data, data)

	encryptedData = data

	return
}

func (a aesMethods) EncryptCbcPkcs5PaddingIvKey16Bytes(data []byte) (key, iv []byte, encryptedData []byte, err error) {
	key, err = EncryptionBox{}.KeyGenerate16Bytes()
	if err != nil {
		return nil, nil, nil, err
	}

	iv, err = EncryptionBox{}.KeyGenerate16Bytes()
	if err != nil {
		return nil, nil, nil, err
	}

	encryptedData, err = a.EncryptCbcPkcs5WithPadding(key, iv, data)
	if err != nil {
		return nil, nil, nil, err
	}

	return key, iv, encryptedData, nil
}

func (a aesMethods) EncryptCbcPKCS5PaddingIvKey24Bytes(data []byte) (key, iv []byte, encryptedData []byte, err error) {
	key, err = EncryptionBox{}.KeyGenerate24Bytes()
	if err != nil {
		return nil, nil, nil, err
	}

	iv, err = EncryptionBox{}.KeyGenerate16Bytes()
	if err != nil {
		return nil, nil, nil, err
	}

	encryptedData, err = a.EncryptCbcPkcs5WithPadding(key, iv, data)
	if err != nil {
		return nil, nil, nil, err
	}

	return key, iv, encryptedData, nil
}

func (a aesMethods) EncryptCbcPkcs5PaddingIvKey32Bytes(data []byte) (key, iv []byte, encryptedData []byte, err error) {
	key, err = EncryptionBox{}.KeyGenerate32Bytes()
	if err != nil {
		return nil, nil, nil, err
	}

	iv, err = EncryptionBox{}.KeyGenerate16Bytes()
	if err != nil {
		return nil, nil, nil, err
	}

	encryptedData, err = a.EncryptCbcPkcs5WithPadding(key, iv, data)
	if err != nil {
		return nil, nil, nil, err
	}

	return key, iv, encryptedData, nil
}

func (a aesMethods) DecryptCbcPkcs5Padding(key, iv, encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCDecrypter(block, iv)

	decryptedData := make([]byte, len(encryptedData))

	cbc.CryptBlocks(decryptedData, encryptedData)

	return EncryptionBox{}.TrimDataPkcs5(decryptedData), nil
}
