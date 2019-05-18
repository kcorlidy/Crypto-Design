package cipher

type Cipher struct {
	left   []byte
	right  []byte
	key    []byte
	nonce  []byte
	rounds int
}

func F(arg []byte, arg2 []byte) []byte {
	arg2 = Mul(arg, arg2)
	return Xor(arg, arg2)
}

func divide(input []byte) *Cipher {
	if len(input)%2 != 0 {
		panic("Invalid input, its length must be multiple of 2")
	}
	x := &Cipher{left: input[:len(input)/2], right: input[len(input)/2:], rounds: 6}
	return x
}

func Feistel_encrypt(plaintext []byte) []byte {
	plain := divide(plaintext)
	temp := make([]byte, len(plain.left))

	subkey := []byte("sadhauw")

	for i := 0; i < plain.rounds; i++ {
		temp = plain.left
		plain.left = plain.right
		plain.right = Xor(temp, F(plain.right, subkey))
	}

	return append(plain.left, plain.right...)
}

func Feistel_decrypt(ciphertext []byte) []byte {
	cipher := divide(ciphertext)
	temp := make([]byte, len(cipher.left))

	subkey := []byte("sadhauw")

	for i := 0; i < cipher.rounds; i++ {
		temp = cipher.right
		cipher.right = cipher.left
		cipher.left = Xor(temp, F(cipher.left, subkey))
	}

	return append(cipher.left, cipher.right...)
}
