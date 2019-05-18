package cipher

func Xor(a []byte, b []byte) []byte {
	new_b := make([]byte, len(a))

	for i := 0; i < len(a); i++ {
		new_b[i] = a[i] ^ b[i]
	}
	return new_b
}

func base(a []byte, b []byte, op func(byte, byte) byte) []byte {
	new_b := make([]byte, len(a))

	for i := 0; i < len(a); i++ {
		new_b[i] = op(a[i], b[i])

		for {

			if new_b[i] > 255 {
				new_b[i] -= 255

			} else if new_b[i] < 0 {
				new_b[i] += 255

			} else {
				break

			}

		}
	}
	return new_b
}

func Mul(a []byte, b []byte) []byte {

	return base(a, b, func(x byte, y byte) byte { return x * y })
}

func Add(a []byte, b []byte) []byte {

	return base(a, b, func(x byte, y byte) byte { return x + y })
}

func Sub(a []byte, b []byte) []byte {

	return base(a, b, func(x byte, y byte) byte { return x - y })
}
