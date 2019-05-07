from binascii import unhexlify, hexlify
import unittest
import base64
import re
import struct

def string_to_int(data):
	"Convert string of bytes Python integer, MSB"
	val = 0
   
	# Python 2.x compatibility
	if type(data) == str:
		data = bytearray(data)

	for (i, c) in enumerate(data[::-1]):
		val += (256**i)*c
	return val

class _baseary(object):
	
	def __init__(self, bytestring=None, _dec=None, _hex=None, _bin=None, base=32):
		self._dec = _dec
		self.base = base
		self.bytestring = bytestring

		if _bin:
			self._dec =	int(_bin, 2)
		if _hex:
			try:
				_hex = hexlify(_hex)
			except Exception as e:
				pass
			self._dec = int(_hex, 16)

		if base == 32:
			self.string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
			self.pad_size = 5
		elif base == 58:
			self.string = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
		elif base == 64:
			self.string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			self.pad_size = 6

	def encode_int(self):
		arr = []
		mod = None
		while self._dec != 0:
			mod = self._dec % self.base
			arr += [mod]
			self._dec = int(self._dec/self.base)

		return "".join(map(lambda n: self.string[n] , arr[::-1])).encode()

	def encode_bytes(self):
		
		bins = "".join(format(i, "#010b")[2:] for i in self.bytestring)

		if self.pad_size == 5:
			padding = len(self.bytestring) % self.pad_size
		elif self.pad_size == 6:
			padding = len(bins) % (self.pad_size * 4)
			
		if padding == 1:
			padding = b'======'
		elif padding == 2:
			padding = b'===='
		elif padding == 3:
			padding = b'==='
		elif padding == 4:
			padding = b'='

		bins = "".join(format(i, "#010b")[2:] for i in self.bytestring)

		while len(bins) % self.pad_size:
			bins = bins + "0"

		to_single = tuple(
					map(lambda x: int(x, 2) , re.findall(r"\d{%d}"%self.pad_size, bins)))

		result = "".join(map(lambda n: self.string[n], to_single)).encode()
		if padding:
			return result + padding
		return result

	def encode_bytes_2(self):

		padding = (-len(self.bytestring)) % 4
		if padding:
			self.bytestring = self.bytestring + b'\0' * padding

		chars = [bytes((i,)) for i in self.string]
		chars2 = [(a + b) for a in chars for b in chars]
		

		sti = string_to_int(self.bytestring)
		words = struct.Struct('!%dI' % (len(self.bytestring) // 4)).unpack(self.bytestring)

		chunks = [
			  (chars2[word // 195112] +
			   chars2[word // 58 % 3364] +
			   chars[word % 58])
			  for word in words]

		return b"".join(chunks)
	
class test(unittest.TestCase):
	
	def test_base32_int(self):
		ary = _baseary(_dec=27830000052)
		a = ary.encode_int()
		ary = _baseary(_hex="67ACC19B4")
		b = ary.encode_int()
		ary = _baseary(_bin="11001111010110011000001100110110100")
		c = ary.encode_int()
		self.assertEqual(a, b)
		self.assertEqual(c, b)

	def _test_base58_int(self):
		ary = _baseary(_dec=27830000052, base=58)
		a = ary.encode_int()
		ary = _baseary(_hex="67ACC19B4", base=58)
		b = ary.encode_int()
		ary = _baseary(_bin="11001111010110011000001100110110100", base=58)
		c = ary.encode_int()
		self.assertEqual(a, b)
		self.assertEqual(c, b)

	def test_base64_int(self):
		ary = _baseary(_dec=27830000052, base=64)
		a = ary.encode_int()
		ary = _baseary(_hex="67ACC19B4", base=64)
		b = ary.encode_int()
		ary = _baseary(_bin="11001111010110011000001100110110100", base=64)
		c = ary.encode_int()
		self.assertEqual(a, b)
		self.assertEqual(c, b)

	def test_base32_bytes(self):
		bytestrings = [b"\x00\xff\x00"*16, b"\xff\xff\xff"*16, b"\x00\x00\x00"*16]
		for bytestring in bytestrings:
			ary = _baseary(bytestring=bytestring)
			a = ary.encode_bytes()
			self.assertEqual(a, base64.b32encode(bytestring))

	def test_base64_bytes(self):
		bytestrings = [b"\x00\xff\x00"*16, b"\xff\xff\xff"*16, b"\x00\x00\x00"*16]
		for bytestring in bytestrings:
			ary = _baseary(bytestring=bytestring, base=64)
			a = ary.encode_bytes()
			self.assertEqual(a, base64.b64encode(bytestring))

	def test_base58_bytes(self):
		bytestrings = [b"\x00\xff\x00\xff\x00", b"c"]
		for bytestring in bytestrings:
			ary = _baseary(bytestring=bytestring, base=58)
			a = ary.encode_bytes_2()
			print(a) # LQX
			

if __name__ == '__main__':

	unittest.main()
	