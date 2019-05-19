package cipher

import (
	//"crypto/sha256"
	"bytes"
	//"fmt"
	"math/big"
)

var __base58_alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
var __base58_radix = big.NewInt(58)

func find(b byte) *big.Int {
	pos := int64(0)
	for p := range __base58_alphabet {
		if __base58_alphabet[p] == b {
			pos = int64(p)
		}
	}
	return big.NewInt(pos)
}

func bytestoint(bytes []byte) *big.Int {

	r := big.NewInt(0)
	pos := len(bytes) - 1 // Reverse
	for i := 0; i < len(bytes); i++ {
		// +=  c * (256**i)
		r.Add(
			// c * (256**i)
			r, big.NewInt(0).Mul(
				// c
				big.NewInt(int64(bytes[pos])),
				// 256**i
				big.NewInt(0).Exp(big.NewInt(256), big.NewInt(int64(i)), nil)))
		pos -= 1
	}
	return r
}

func B58encode(data []byte) []byte {

	output := make([]byte, 0)
	val := bytestoint(data)
	mod := big.NewInt(0)
	for {
		if val.Cmp(__base58_radix) != -1 {
			val, mod = big.NewInt(0).DivMod(val, __base58_radix, mod)
			output = append(output, __base58_alphabet[mod.Int64()])
		} else {
			break
		}
	}
	if val.Cmp(big.NewInt(0)) != -1 {
		output = append(output, __base58_alphabet[val.Int64()])
	}

	for i := 0; i < len(data)-len(bytes.Trim(data, "\x00")); i++ {
		output = append(output, __base58_alphabet[0])
	} // Prefix

	for i, j := 0, len(output)-1; i < j; i, j = i+1, j-1 {
		output[i], output[j] = output[j], output[i]
	} // Reverse

	return output
}

func B58decode(data []byte) []byte {
	result := make([]byte, 0)
	val, mod, mod_num := big.NewInt(0), big.NewInt(0), big.NewInt(256)

	pos := len(data) - 1
	for i := range data {
		val.Add(val, big.NewInt(1).Mul(find(data[pos-i]), big.NewInt(1).Exp(__base58_radix, big.NewInt(int64(i)), nil)))

	}
	for {
		if val.Cmp(mod_num) == -1 {
			break
		}
		val, mod = val.DivMod(val, mod_num, mod)
		result = append(result, mod.Bytes()[0])
	}
	if val.Cmp(big.NewInt(0)) > -1 {
		result = append(result, byte(val.Int64()))
	}

	for i := range data {
		if data[i] != []byte("1")[0] {
			break
		}
		result = append(result, []byte("\x00")[0])
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	} // Reverse

	return result
}

func B58encode_check() {

}

func B58decode_check() {

}
