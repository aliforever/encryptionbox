package encryptionbox

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

type rsaMethods struct {
}

func (r rsaMethods) Generate1024Bits() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	return
}

func (r rsaMethods) Generate2048Bits() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	return
}

func (r rsaMethods) Generate4096Bits() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	return
}

func (r rsaMethods) PrivateKeyToPKCS1PEM(privateKey *rsa.PrivateKey) (pemBytes []byte, err error) {
	var privateKeyBytes []byte
	privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	var b bytes.Buffer
	err = pem.Encode(&b, privateKeyBlock)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when encoding private key to pem: %s", err))
		return
	}
	pemBytes = b.Bytes()
	return
}

func (r rsaMethods) PublicKeyToPKCS1PEM(publicKey *rsa.PublicKey) (pemBytes []byte, err error) {
	var publicKeyBytes []byte
	publicKeyBytes = x509.MarshalPKCS1PublicKey(publicKey)
	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	var b bytes.Buffer
	err = pem.Encode(&b, publicKeyBlock)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when encoding public key to pem: %s", err))
		return
	}
	pemBytes = b.Bytes()
	return
}

func (r rsaMethods) PublicKeyToPKIXPEM(publicKey *rsa.PublicKey) (pemBytes []byte, err error) {
	var publicKeyBytes []byte
	publicKeyBytes, err = x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}
	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	var b bytes.Buffer
	err = pem.Encode(&b, publicKeyBlock)
	if err != nil {
		err = errors.New(fmt.Sprintf("error when encoding public key to pem: %s", err))
		return
	}
	pemBytes = b.Bytes()
	return
}

func (r rsaMethods) PrivateKeyFromPKCS1PEMBytes(pemBytes []byte) (privateKey *rsa.PrivateKey, err error) {
	var block *pem.Block
	block, _ = pem.Decode(pemBytes)
	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	return
}

func (r rsaMethods) PrivateKeyFromPKCS1PEMFile(pemPath string) (privateKey *rsa.PrivateKey, err error) {
	var pemBytes []byte
	pemBytes, err = ioutil.ReadFile(pemPath)
	if err != nil {
		return
	}
	privateKey, err = r.PrivateKeyFromPKCS1PEMBytes(pemBytes)
	return
}

func (r rsaMethods) PublicKeyFromPKCS1PEMBytes(pemBytes []byte) (publicKey *rsa.PublicKey, err error) {
	var block *pem.Block
	block, _ = pem.Decode(pemBytes)
	publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	return
}

func (r rsaMethods) PublicKeyFromPKCS1PEMPath(pemPath string) (publicKey *rsa.PublicKey, err error) {
	var pemBytes []byte
	pemBytes, err = ioutil.ReadFile(pemPath)
	if err != nil {
		return
	}
	publicKey, err = r.PublicKeyFromPKCS1PEMBytes(pemBytes)
	return
}

func (r rsaMethods) PublicKeyFromPKIXPEMBytes(pemBytes []byte) (publicKey *rsa.PublicKey, err error) {
	var block *pem.Block
	block, _ = pem.Decode(pemBytes)

	var pub interface{}
	pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}
	publicKey = pub.(*rsa.PublicKey)
	return
}

func (r rsaMethods) PublicKeyFromPKIXPEMPath(pemPath string) (publicKey *rsa.PublicKey, err error) {
	var pemBytes []byte
	pemBytes, err = ioutil.ReadFile(pemPath)
	if err != nil {
		return
	}
	publicKey, err = r.PublicKeyFromPKIXPEMBytes(pemBytes)
	return
}

func (r rsaMethods) PrivateKeyDecryptPKCS1v15(privateKey *rsa.PrivateKey, encryptedData []byte) (decryptedData []byte, err error) {
	decryptedData, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedData)
	return
}

func (r rsaMethods) PrivateKeyDecryptPKCS1v15SessionKey(privateKey *rsa.PrivateKey, encryptedData, key []byte) (err error) {
	err = rsa.DecryptPKCS1v15SessionKey(rand.Reader, privateKey, encryptedData, key)
	return
}

func (r rsaMethods) PrivateKeyDecryptOAEPSHA1(privateKey *rsa.PrivateKey, encryptedData, label []byte) (decryptedData []byte, err error) {
	decryptedData, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, encryptedData, label)
	return
}

func (r rsaMethods) PrivateKeyDecryptOAEPSHA256(privateKey *rsa.PrivateKey, encryptedData, label []byte) (decryptedData []byte, err error) {
	decryptedData, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedData, label)
	return
}

func (r rsaMethods) PrivateKeyDecryptMD5(privateKey *rsa.PrivateKey, encryptedData, label []byte) (decryptedData []byte, err error) {
	decryptedData, err = rsa.DecryptOAEP(md5.New(), rand.Reader, privateKey, encryptedData, label)
	return
}

func (r rsaMethods) PublicKeyEncryptPKCS1v15(publicKey *rsa.PublicKey, data []byte) (encryptedData []byte, err error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
}

func (r rsaMethods) PublicKeyEncryptOAEPSHA1(publicKey *rsa.PublicKey, data, label []byte) (encryptedData []byte, err error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, data, label)
}

func (r rsaMethods) PublicKeyEncryptOAEPSHA256(publicKey *rsa.PublicKey, data, label []byte) (encryptedData []byte, err error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, label)
}

func (r rsaMethods) PublicKeyEncryptOAEPMD5(publicKey *rsa.PublicKey, data, label []byte) (encryptedData []byte, err error) {
	return rsa.EncryptOAEP(md5.New(), rand.Reader, publicKey, data, label)
}
