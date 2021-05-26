package tests

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/aliforever/encryptionbox"
)

func TestAESCBC(t *testing.T) {
	box := encryptionbox.EncryptionBox{}
	key, err := box.KeyGenerate32Bytes()
	if err != nil {
		fmt.Println(err)
		return
	}
	key = []byte{176, 118, 143, 64, 140, 215, 34, 135, 86, 77, 87, 197, 147, 86, 162, 143, 152, 56, 225, 100, 198, 250, 119, 223, 119, 167, 15, 228, 128, 95, 22, 39}
	fmt.Println("key", key)
	fmt.Println("key base64", base64.StdEncoding.EncodeToString(key))
	fmt.Println("key hex", hex.EncodeToString(key))
	fmt.Println("key length", len(key), "bytes -", len(key)*8, "bits")
	iv, err := box.KeyGenerate16Bytes()
	if err != nil {
		fmt.Println(err)
		return
	}
	iv = []byte{160, 112, 246, 246, 74, 243, 27, 18, 247, 36, 3, 249, 137, 25, 127, 155}
	fmt.Println("iv", iv)
	fmt.Println("iv hex", hex.EncodeToString(iv))
	data := []byte("salam")
	fmt.Println("data", data)
	encrypted, err := box.AES.AESEncryptCBCPKCS5Padding(key, iv, data)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("encrypted", encrypted)

	decrypted, err := box.AES.AESDecryptCBCPKCS5Padding(key, iv, encrypted)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("decrypted", decrypted)
	key = []byte{176, 118, 143, 64, 140, 215, 34, 135, 86, 77, 87, 197, 147, 86, 162, 143, 152, 56, 225, 100, 198, 250, 119, 223, 119, 167, 15, 228, 128, 95, 22, 39}
	encrypted = []byte{93, 178, 214, 48, 87, 63, 198, 117, 224, 44, 244, 197, 111, 52, 255, 56}
	decrypted, err = box.AES.AESDecryptCBCPKCS5Padding(key, iv, encrypted)
	fmt.Println(string(decrypted), err)
}
