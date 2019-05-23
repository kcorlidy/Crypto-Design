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
	// 24930 b'\x00\x00ab' 118Qq python
	// 25185   \x00\x00ab  118Qq go
	plaintext := []byte("\x00\x00ab")
	ciphertext := cipher.B58encode(plaintext)
	plaintext_ := cipher.B58decode(ciphertext)
	fmt.Printf("ciphertext:%s plaintext:%s origin_text:%s\n", ciphertext, plaintext_, plaintext)
}

func test_bech32() {

	witver, witprog := cipher.Bech32decode([]byte("bc"),
		[]byte("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"))
	scriptpubkey_ := cipher.Segwit_scriptpubkey(witver, witprog)
	fmt.Println(scriptpubkey_)

	key := []byte("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c")
	value := cipher.Bech32encode([]byte("bc"), key)
	fmt.Printf("%s\n", value)
}

func main() {
	test_feistel()
	test_sbox()
	test_base58()
	test_bech32()
}
