package cipher

import (
// "encoding/binary"
//"fmt"
)

type Box struct {
	Forward  [16][16]byte
	Backward map[byte][]int
}

type funcx func([]byte, int, int) int

func New_box(key []byte, bf funcx) *Box {
	box := new(Box)
	check_set := make([]int, 256, 256)
	value := 1
	box.Backward = make(map[byte][]int)
	// Forward Box
	for r := 0; r < 16; r++ {
		for c := 0; c < 16; c++ {
			value = bf(key, r, c)

			for {
				if value > 255 {
					value -= 256
					continue
				}
				if check_set[value] == 0 {
					check_set[value] = 1
					break
				} else {
					value += 1
				}
			}
			box.Forward[r][c] = byte(value)
			box.Backward[byte(value)] = append(box.Backward[byte(value)], r, c)
		}
	}

	return box
}

func Bent_fuc(arg []byte, r int, c int) int {
	vector := 0
	for b := range arg {
		vector ^= int(b) ^ (r * (c * c))
		if r+c == 32 {
			break
		} else {
			r += 1
		}

	}
	return vector
}

func (box *Box) Select_cipher(plaintext []byte) []byte {
	ciphertext := make([]byte, 0)
	pos := 0
	for plain := range plaintext {
		pos = int(plaintext[plain])
		ciphertext = append(ciphertext, box.Forward[pos>>4][((pos>>4)<<4)^pos])
	}
	return ciphertext
}

func (box *Box) Select_plain(ciphertext []byte) []byte {
	plaintext := make([]byte, 0)
	pos := (*new(byte))
	for c := range ciphertext {
		pos = ciphertext[c]
		plaintext = append(plaintext, byte(int(box.Backward[pos][0]<<4)+int(box.Backward[pos][1])))
	}
	return plaintext
}
