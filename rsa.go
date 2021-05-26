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

func (r rsaMethods) RSAGenerate1024Bits() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	return
}

func (r rsaMethods) RSAGenerate2048Bits() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	return
}

func (r rsaMethods) RSAGenerate4096Bits() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	return
}

func (r rsaMethods) RSAPrivateKeyToPKCS1PEM(privateKey *rsa.PrivateKey) (pemBytes []byte, err error) {
	var privateKeyBytes []byte
	privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "rsaMethods PRIVATE KEY",
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

func (r rsaMethods) RSAPublicKeyToPKCS1PEM(publicKey *rsa.PublicKey) (pemBytes []byte, err error) {
	var publicKeyBytes []byte
	publicKeyBytes = x509.MarshalPKCS1PublicKey(publicKey)
	publicKeyBlock := &pem.Block{
		Type:  "rsaMethods PUBLIC KEY",
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

func (r rsaMethods) RSAPublicKeyToPKIXPEM(publicKey *rsa.PublicKey) (pemBytes []byte, err error) {
	var publicKeyBytes []byte
	publicKeyBytes, err = x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}
	publicKeyBlock := &pem.Block{
		Type:  "rsaMethods PUBLIC KEY",
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

func (r rsaMethods) RSAPrivateKeyFromPKCS1PEMBytes(pemBytes []byte) (privateKey *rsa.PrivateKey, err error) {
	var block *pem.Block
	block, _ = pem.Decode(pemBytes)
	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	return
}

func (r rsaMethods) RSAPrivateKeyFromPKCS1PEMFile(pemPath string) (privateKey *rsa.PrivateKey, err error) {
	var pemBytes []byte
	pemBytes, err = ioutil.ReadFile(pemPath)
	if err != nil {
		return
	}
	privateKey, err = r.RSAPrivateKeyFromPKCS1PEMBytes(pemBytes)
	return
}

func (r rsaMethods) RSAPublicKeyFromPKCS1PEMBytes(pemBytes []byte) (publicKey *rsa.PublicKey, err error) {
	var block *pem.Block
	block, _ = pem.Decode(pemBytes)
	publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	return
}

func (r rsaMethods) RSAPublicKeyFromPKCS1PEMPath(pemPath string) (publicKey *rsa.PublicKey, err error) {
	var pemBytes []byte
	pemBytes, err = ioutil.ReadFile(pemPath)
	if err != nil {
		return
	}
	publicKey, err = r.RSAPublicKeyFromPKCS1PEMBytes(pemBytes)
	return
}

func (r rsaMethods) RSAPublicKeyFromPKIXPEMBytes(pemBytes []byte) (publicKey *rsa.PublicKey, err error) {
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

func (r rsaMethods) RSAPublicKeyFromPKIXPEMPath(pemPath string) (publicKey *rsa.PublicKey, err error) {
	var pemBytes []byte
	pemBytes, err = ioutil.ReadFile(pemPath)
	if err != nil {
		return
	}
	publicKey, err = r.RSAPublicKeyFromPKIXPEMBytes(pemBytes)
	return
}

func (r rsaMethods) RSAPrivateKeyDecryptPKCS1v15(privateKey *rsa.PrivateKey, encryptedData []byte) (decryptedData []byte, err error) {
	decryptedData, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedData)
	return
}

func (r rsaMethods) RSAPrivateKeyDecryptPKCS1v15SessionKey(privateKey *rsa.PrivateKey, encryptedData, key []byte) (err error) {
	err = rsa.DecryptPKCS1v15SessionKey(rand.Reader, privateKey, encryptedData, key)
	return
}

func (r rsaMethods) RSAPrivateKeyDecryptOAEPSHA1(privateKey *rsa.PrivateKey, encryptedData, label []byte) (decryptedData []byte, err error) {
	decryptedData, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, encryptedData, label)
	return
}

func (r rsaMethods) RSAPrivateKeyDecryptOAEPSHA256(privateKey *rsa.PrivateKey, encryptedData, label []byte) (decryptedData []byte, err error) {
	decryptedData, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedData, label)
	return
}

func (r rsaMethods) RSAPrivateKeyDecryptMD5(privateKey *rsa.PrivateKey, encryptedData, label []byte) (decryptedData []byte, err error) {
	decryptedData, err = rsa.DecryptOAEP(md5.New(), rand.Reader, privateKey, encryptedData, label)
	return
}

func (r rsaMethods) RSAPublicKeyEncryptPKCS1v15(publicKey *rsa.PublicKey, data []byte) (encryptedData []byte, err error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
}

func (r rsaMethods) RSAPublicKeyEncryptOAEPSHA1(publicKey *rsa.PublicKey, data, label []byte) (encryptedData []byte, err error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, data, label)
}

func (r rsaMethods) RSAPublicKeyEncryptOAEPSHA256(publicKey *rsa.PublicKey, data, label []byte) (encryptedData []byte, err error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, label)
}

func (r rsaMethods) RSAPublicKeyEncryptOAEPMD5(publicKey *rsa.PublicKey, data, label []byte) (encryptedData []byte, err error) {
	return rsa.EncryptOAEP(md5.New(), rand.Reader, publicKey, data, label)
}
