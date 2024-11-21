package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
)

const (
	xorKey = "HelpMeWinlezPlz?"
	aesKey = "SupeRSecrET145*$"
)

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func aesEncrypt(originalData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	originalData = pkcs5Padding(originalData, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])

	crypted := make([]byte, len(originalData))

	blockMode.CryptBlocks(crypted, originalData)

	return crypted, nil
}

func printFormattedByteSlice(slice []byte) {
	fmt.Print("byteSlice := []byte{")
	for i, b := range slice {
		fmt.Printf("%d", b)
		if i < len(slice)-1 {
			fmt.Print(",")
		}
	}
	fmt.Println("}")
}

func main() {
	// Read content binary file
	fileContent, err := ioutil.ReadFile("met.bin")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// XOR
	xoredData := make([]byte, len(fileContent))
	for i := range fileContent {
		xoredData[i] = fileContent[i] ^ xorKey[i%len(xorKey)]
	}

	// AES encryption
	encryptedData, err := aesEncrypt(xoredData, []byte(aesKey))
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}

	// Print formatted byte slice
	printFormattedByteSlice(encryptedData)
}
