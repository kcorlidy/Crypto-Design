from binascii import unhexlify, hexlify
import unittest
import re
import warnings
from random import randint, seed
import sys

class block(object):
	"""
	block_size: block size should equal to the size of key or IV. block_size -> 8, 16, 32.
	extending:  Extending blocks to 64, 128, etc. 
				If block size is not multi of 8 and do not equal to key size, don't use it.
				0 -> remove 1 -> add 2 -> nothing
	plaintext:	just plaintext
	ciphertext:	if it is ciphertext it may be hex, so we have to unhexlify it.
	plaintext_size:	this will be used when compute the padding size.

	TODO: i want to add padding into blocks function, also the extending function. So we can do everything easier.
	"""
	def __init__(self, block_size=16, plaintext=None, ciphertext=None, 
					padding=None, inverse=False, extending=2):
		if ciphertext and not plaintext:
			try:
				plaintext = unhexlify(ciphertext)
			except Exception as e:
				plaintext = ciphertext

		elif ciphertext and plaintext:
			raise AttributeError("only one it need, ciphertext or plaintext")

		self.padding = padding
		self.inverse = inverse
		self.extending = extending 
		self.block_size = block_size if isinstance(block_size, int) else len(block_size)
		self.plaintext = plaintext
		self.plaintext_size = len(plaintext)
		self.blocks()

	def toint(self,value):
		
		return int(self.tobin(value), 2)

	def tobin(self,value):
		try:
			b = ''.join(format(ord(x), '#010b')[2:] for x in value)
		except Exception as e:
			try:
				b = ''.join(format(x, '#010b')[2:] for x in value)
			except Exception as e:
				b = ''.join(format(value, '#010b')[2:])
		while len(b)%8:
			b = "0" + b
		return b

	def padding_size(self):

		if self.plaintext_size > self.block_size:
			# plaintext size > block size
			for i in range(100000):
				mod = (self.block_size * i) - self.plaintext_size
				if mod >= 0:
					break

		elif self.plaintext_size < self.block_size:
			mod = self.block_size - self.plaintext_size
		else:
			mod = 0

		return mod

	"""
	b'abcdefghijk\x01' is obvious enough to know \x01 is a padding-number.
	But b'\x01\x01\x01\x01' is impossible. So what we can do is let it go.
	"""
	def paddingANSIX923(self, inverse=False):

		if inverse:
			# situation 1: \x01
			# situation 2: \x02 or bigger
			mark = - self.plaintext[-1]
			if - mark < len(self.plaintext):
				# check again, if found \xff\xff\x12\x04 that said it is wrong.
				self.plaintext = self.plaintext[:mark] if self.plaintext[mark - 1: -1].replace(b"\x00", b"") else self.plaintext
			return

		mod = self.padding_size()
		if not mod:
			return
		i = 0
		self.plaintext += i.to_bytes(1, sys.byteorder) * (mod - 1) + mod.to_bytes(1, sys.byteorder)

	def paddingISO10126(self, inverse=False):
		
		if inverse:
			mark = - self.plaintext[-1]
			if - mark < len(self.plaintext):
				# ISO 10126 used random byte so we can make a double check.
				self.plaintext = self.plaintext[:mark]
				return

		mod = self.padding_size()
		if not mod:
			return

		size_mark = mod.to_bytes(1, sys.byteorder)
		self.plaintext += b"".join([randint(0,255).to_bytes(1, sys.byteorder) for _ in range(mod - 1)]) + size_mark
		

	def paddingPKCS7(self, inverse=False):

		if inverse:
			mark = - self.plaintext[-1]
			if - mark < len(self.plaintext):
				self.plaintext = self.plaintext[:mark] if len(set(self.plaintext[mark: -1])) <= 1 else self.plaintext
			return self.plaintext

		mod = self.padding_size()
		if not mod:
			return

		self.plaintext += mod.to_bytes(1, sys.byteorder) * mod
	

	def paddingISOIEC7816_4(self, inverse=False):
		"""
		In ISO/IEC 7816-4
		 | DD DD DD DD DD DD DD DD | DD DD DD DD 80 00 00 00 |
		 | DD DD DD DD DD DD DD DD | DD DD DD DD DD DD DD 80 |
		But \x80 is `P`, so i decide change it to the max size \xf5. \xff is using.
		"""
		if inverse:
			l = re.findall(b"(\xf5\x00{0,})$", self.plaintext)
			if l:
				self.plaintext = self.plaintext.strip(l[-1])
			return self.plaintext

		mod = self.padding_size()
		if not mod:
			return
		i = 245
		i2 = 0
		self.plaintext += i.to_bytes(1, sys.byteorder) + i2.to_bytes(1, sys.byteorder) * (mod - 1)


	def paddingxff(self, inverse=False):
		if inverse:
			l = re.findall(b"(\xff+)$", self.plaintext)
			if l:
				self.plaintext = self.plaintext.strip(l[-1])
			return self.plaintext

		mod = self.padding_size()
		if not mod:
			return
		i = 255
		self.plaintext += i.to_bytes(1, sys.byteorder) * mod

	def blocks(self):
		"""
		remove what we added before
		"""
		inverse = self.inverse
		padding = self.padding
		if self.extending == 0:
			self.remove_extending()

		if padding == "xff":
			self.paddingxff(inverse)

		elif padding == "ISOIEC7816_4":
			self.paddingISOIEC7816_4(inverse)

		elif padding == "PKCS7":
			self.paddingPKCS7(inverse)

		elif padding == "ISO10126":
			self.paddingISO10126(inverse)

		elif padding == "ANSIX923":
			self.paddingANSIX923(inverse)
	

		count = 1
		output = [self.plaintext[:self.block_size * count]]
		while self.block_size * count <= self.plaintext_size:
			output.append(self.plaintext[self.block_size * count: self.block_size * (count+1)])
			count +=1

		self._block = list(filter(lambda x:x, output))
		
		
		if self.extending == 1:
			self._block = self.block_extend(self._block)
			return self

		return self


	@property
	def blocks_int(self):
		return [self.toint(b) for b in self._block]


class test(unittest.TestCase):

	def test_padding(self):
		# it is useless to special bytes.
		func = ["PKCS7", "ISO10126", "xff", "ANSIX923", "ISOIEC7816_4"]
		for f in func:
			print(f)
			# plaintext size < block size
			b = block(plaintext=b"abcd", padding=f)._block
			b = block(plaintext=b"".join(b), padding=f, inverse=True)._block
			self.assertEqual(b"".join(b), b"abcd")

			b = block(plaintext=b"abcdefghijk", padding=f)._block
			b = block(plaintext=b"".join(b), padding=f, inverse=True)._block
			self.assertEqual(b"".join(b), b"abcdefghijk")
			
			# plaintext size > block size
			b = block(plaintext=b"abcdefghijkabcdefghijkabcdefghijk", padding=f)._block
			b = block(plaintext=b"".join(b), padding=f, inverse=True)._block
			self.assertEqual(b"".join(b), b"abcdefghijkabcdefghijkabcdefghijk")

			# plaintext size = block size
			b = block(plaintext=b"abcdefghijklmnop", padding=f)._block
			b = block(plaintext=b"".join(b), padding=f, inverse=True)._block
			self.assertEqual(b"".join(b), b"abcdefghijklmnop")

	def test_block_extending(self):
		#b = block(plaintext=b"efgh", block_size=8)
		pass

if __name__ == '__main__':

	unittest.main()