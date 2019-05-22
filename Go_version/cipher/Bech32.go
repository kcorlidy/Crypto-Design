package cipher

import (
	//"fmt"
	"bytes"
	"encoding/binary"
)

var CHARSET = []byte("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

func Bech32encode(hrp []byte, witver int, witprog []byte) []byte {
	bs := make([]byte, 0)
	binary.LittleEndian.PutUint32(bs, uint32(witver))
	ret := encode(hrp, append(bs, convertbits(witprog, 8, 5, true)...))
	Bech32decode(hrp, ret)
	return ret
}

func Bech32decode(hrp []byte, addr []byte) (byte, []byte) {
	hrpgot, data := decode(addr)
	if !bytes.Equal(hrpgot, hrp) {
		panic("decode error")
	}
	decoded := convertbits(data[1:], 5, 8, false)
	if decoded == nil || len(decoded) < 2 || len(decoded) > 40 {
		panic("decode error")
	}
	if data[0] > 16 {
		panic("decode error")
	}
	if data[0] == 0 && len(decoded) != 20 && len(decoded) != 32 {
		panic("decode error")
	}
	return data[0], decoded
}

func decode(bech []byte) ([]byte, []byte) {
	for x := range bech {
		if bech[x] < 33 || bech[x] > 126 {
			panic("decode error")
		}
	}
	if !bytes.Equal(bytes.ToLower(bech), bech) && !bytes.Equal(bytes.ToUpper(bech), bech) {
		panic("decode error")
	}
	bech = bytes.ToLower(bech)
	pos := bytes.LastIndexByte(bech, []byte("1")[0])
	if pos < 1 || pos+7 > len(bech) || len(bech) > 90 {
		panic("decode error")
	}
	for x := range bech[pos+1:] {
		if bytes.IndexByte(CHARSET, bech[pos+1+x]) < 0 {
			panic("decode error")
		}
	}
	hrp := bech[:pos]
	data := make([]byte, 0)
	for x := range bech[pos+1:] {
		data = append(data, CHARSET[bytes.IndexByte(bech[pos+1:], bech[pos+1+x])])
	}
	if bech32_verify_checksum(hrp, data) != true {
		panic("decode error")
	}
	return hrp, data[:len(data)-6]
}

func encode(hrp []byte, data []byte) []byte {
	combined := append(data, bech32_create_checksum(hrp, data)...)
	result := make([]byte, 0)
	for d := range combined {
		result = append(result, CHARSET[d])
	}
	return append(append(hrp, []byte("1")...), result...)
}

func convertbits(data []byte, frombits uint, tobits uint, pad bool) []byte {
	acc := 0
	bits := uint(0)
	ret := make([]byte, 0)
	maxv := (1 << tobits) - 1
	max_acc := (1 << (frombits + tobits - 1)) - 1
	value := 0
	for p := range data {
		value = int(data[p])
		if value < 0 || (value>>frombits) > 0 {
			return nil
		}
		acc = ((acc << frombits) | value) & max_acc
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, byte((acc>>bits)&maxv))
		}
	}
	if pad == true {
		if bits != 0 {
			ret = append(ret, byte((acc<<(tobits-bits))&maxv))
		}
	} else if bits >= frombits || ((acc<<(tobits-bits))&maxv) > 0 {
		return nil
	}
	return ret

}

func bech32_polymod(values []byte) byte {
	// Internal function that computes the Bech32 checksum.
	generator := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk, top := 1, 0
	for p := range values {
		top = chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ int(values[p])
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 > 0 {
				chk ^= generator[i]
			} else {
				chk ^= 0
			}
		}
	}
	return byte(chk)

}

func bech32_hrp_expand(hrp []byte) []byte {
	ar1, ar2 := make([]byte, 0), make([]byte, 0)
	for hr1 := range hrp {
		ar1[hr1] = hrp[hr1] >> 5
	}
	for hr2 := range hrp {
		ar2[hr2] = hrp[hr2] & 31
	}
	return append(append(ar2, byte(0)), ar2...)
}

func bech32_verify_checksum(hrp []byte, data []byte) bool {
	if bech32_polymod(append(bech32_hrp_expand(hrp), data...)) == 1 {
		return true
	}
	return false
}

func bech32_create_checksum(hrp []byte, data []byte) []byte {
	values := append(bech32_hrp_expand(hrp), data...)
	polymod := bech32_polymod(append(values, []byte{0, 0, 0, 0, 0, 0}...)) ^ 1
	ar := make([]byte, 0)
	for i := 0; i < 6; i++ {
		ar[i] = byte((int(polymod) >> 5 * (5 - i)) & 31)
	}
	return ar
}
