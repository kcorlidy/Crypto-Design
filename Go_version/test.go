package main

import (
	cipher "./cipher"
	"fmt"
)

func test_feistel() {

	p := []byte("1234")
	ciphertext := cipher.Feistel_encrypt(p)
	plaintext_ := cipher.Feistel_decrypt(ciphertext)
	fmt.Printf("ciphertext:%s plaintext:%s origin_text:%s\n", ciphertext, plaintext_, p)

}

func test_sbox() {
	key := []byte("key")
	plaintext := []byte("hello")
	ciphertext := cipher.New_box(key, cipher.Bent_fuc).Select_cipher(plaintext)
	plaintext_ := cipher.New_box(key, cipher.Bent_fuc).Select_plain(ciphertext)
	fmt.Printf("ciphertext:%s plaintext:%s origin_text:%s\n", ciphertext, plaintext_, plaintext)
}

func test_base58() {

}

func main() {
	test_feistel()
	test_sbox()
}
