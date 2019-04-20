from binascii import unhexlify, hexlify
import unittest
import re
import warnings
from random import randint
from functools import reduce
import sys

class block(object):
	"""
	vector can be `key` or `IV`
	"""
	def __init__(self, vector, plaintext=None, ciphertext=None):
		if ciphertext and not plaintext:
			try:
				plaintext = unhexlify(ciphertext)
			except Exception as e:
				plaintext = ciphertext

		elif ciphertext and plaintext:
			raise AttributeError("only one it need, ciphertext or plaintext")

		self.block_size = len(vector)
		self.plaintext = plaintext
		self.plaintext_size = len(plaintext)
		if self.block_size > 255:
			warnings.warn("block_size is too large that padding function can not output correctly.")

	def toint(self,value):
		
		return int(self.tobin(value), 2)

	def tobin(self,value,binstring=False):
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
			mod = (self.block_size * (self.plaintext_size % self.block_size)) - self.plaintext_size
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
		"""
		I think `ff`(\xff) is rare enough compare to `00`(\x00), so i changed it
		"""
		if inverse:
			# situation 1: \x01
			# situation 2: \x02 or bigger
			mark = - self.plaintext[-1]
			if - mark < self.plaintext_size:
				# check again, if found \xff\xff\x12\x04 that said it is wrong.
				self.plaintext = self.plaintext[:mark] if self.plaintext[mark - 1: -1].replace(b"\xff", b"") else self.plaintext
			return self.plaintext

		mod = self.padding_size()
		if not mod:
			return self.plaintext
		i = 255
		self.plaintext += i.to_bytes(1, sys.byteorder) * (mod - 1) + mod.to_bytes(1, sys.byteorder)
		return self.plaintext

	def paddingISO10126(self, inverse=False):
		
		if inverse:
			mark = - self.plaintext[-1]
			if - mark < self.plaintext_size:
				# ISO 10126 used random byte so we can make a double check.
				self.plaintext = self.plaintext[:mark]

			return self.plaintext

		mod = self.padding_size()
		if not mod:
			return self.plaintext
		size_mark = mod.to_bytes(1, sys.byteorder)
		self.plaintext += b"".join([randint(0,255).to_bytes(1, sys.byteorder) for _ in range(mod - 1)]) + size_mark
		return self.plaintext
	

	def paddingPKCS7(self, inverse=False):

		if inverse:
			mark = - self.plaintext[-1]
			if - mark < self.plaintext_size:
				self.plaintext = self.plaintext[:mark] if len(set(self.plaintext[mark: -1])) <= 1 else self.plaintext
			return self.plaintext

		mod = self.padding_size()
		if not mod:
			return self.plaintext
		self.plaintext += mod.to_bytes(1, sys.byteorder) * mod
		return self.plaintext
		if inverse:
			pass

	def paddingISOIEC7816_4(self, inverse=False):
		"""
		In ISO/IEC 7816-4
		 | DD DD DD DD DD DD DD DD | DD DD DD DD 80 00 00 00 |
		 | DD DD DD DD DD DD DD DD | DD DD DD DD DD DD DD 80 |
		But \x80 is `P`, so i decide change it to the max size \xff
		"""
		if inverse:
			l = re.findall(b"(\xff\x00{0,})$", self.plaintext)
			if l:
				self.plaintext = self.plaintext.strip(l[-1])
			return self.plaintext

		mod = self.padding_size()
		if not mod:
			return self.plaintext
		i = 255
		i2 = 0
		self.plaintext += i.to_bytes(1, sys.byteorder) + i2.to_bytes(1, sys.byteorder) * (mod - 1)
		return self.plaintext

	def paddingxff(self, inverse=False):
		if inverse:
			l = re.findall(b"(\xff+)$", self.plaintext)
			if l:
				self.plaintext = self.plaintext.strip(l[-1])
			return self.plaintext

		mod = self.padding_size()
		if not mod:
			return self.plaintext
		i = 255
		self.plaintext += i.to_bytes(1, sys.byteorder) * mod
		return self.plaintext

	@property
	def blocks(self):

		count = 1
		output = [self.plaintext[:self.block_size * count]]
		while self.block_size * count <= self.plaintext_size:
			output.append(self.plaintext[self.block_size * count: self.block_size * (count+1)])
			count +=1

		return filter(lambda x:x, output)

	@property
	def blocks_int(self):
		return [self.toint(b) for b in self.blocks]
		

class test(unittest.TestCase):

	def test_paddingPKCS7(self):

		# plaintext size < block size
		b = block(plaintext=b"abcd", vector=b"abcdefghijk")
		new_p = b.paddingPKCS7()
		self.assertNotEqual(len(new_p) - len(b"abcdefghijk"), -1)
		self.assertEqual(len(new_p) % len(b"abcdefghijk"), 0)

		b = block(plaintext=new_p, vector=b"abcdefghijk")
		old_p = b.paddingPKCS7(inverse=True)
		self.assertEqual(old_p, b"abcd")

		# plaintext size > block size
		b = block(plaintext=b"abcdefghijk", vector=b"abcd")
		new_p = b.paddingPKCS7()
		self.assertNotEqual(len(new_p) - len(b"abcd"), -1)
		self.assertEqual(len(new_p) % len(b"abcd"), 0)


		b = block(plaintext=new_p, vector=b"abcd")
		old_p = b.paddingPKCS7(inverse=True)
		self.assertEqual(old_p, b"abcdefghijk")

		# plaintext size = block size
		b = block(plaintext=b"efgh", vector=b"abcd")
		new_p = b.paddingPKCS7()
		self.assertNotEqual(len(new_p) - len(b"abcd"), -1)
		self.assertEqual(len(new_p) % len(b"abcd"), 0)

		b = block(plaintext=new_p, vector=b"abcd")
		old_p = b.paddingPKCS7(inverse=True)
		self.assertEqual(old_p, b"efgh")

	def test_paddingISO10126(self):

		# plaintext size < block size
		b = block(plaintext=b"abcd", vector=b"abcdefghijk")
		new_p = b.paddingISO10126()
		self.assertNotEqual(len(new_p) - len(b"abcdefghijk"), -1)
		self.assertEqual(len(new_p) % len(b"abcdefghijk"), 0)
		
		b = block(plaintext=new_p, vector=b"abcdefghijk")
		old_p = b.paddingISO10126(inverse=True)
		self.assertEqual(old_p,b"abcd")

		# plaintext size > block size
		b = block(plaintext=b"abcdefghijk", vector=b"abcd")
		new_p = b.paddingISO10126()
		self.assertNotEqual(len(new_p) - len(b"abcd"), -1)
		self.assertEqual(len(new_p) % len(b"abcd"), 0)

		b = block(plaintext=new_p, vector=b"abcd")
		old_p = b.paddingISO10126(inverse=True)
		self.assertEqual(old_p, b"abcdefghijk")

		# plaintext size = block size

		b = block(plaintext=b"efgh", vector=b"abcd")
		new_p = b.paddingISO10126()
		self.assertNotEqual(len(new_p) - len(b"abcd"), -1)
		self.assertEqual(len(new_p) % len(b"abcd"), 0)

		b = block(plaintext=new_p, vector=b"abcd")
		old_p = b.paddingISO10126(inverse=True)
		self.assertEqual(old_p, b"efgh")

	def test_paddingANSIX923(self):

		# plaintext size < block size
		b = block(plaintext=b"abcd", vector=b"abcdefghijk")
		new_p = b.paddingANSIX923()
		self.assertNotEqual(len(new_p) - len(b"abcdefghijk"), -1)
		self.assertEqual(len(new_p) % len(b"abcdefghijk"), 0)

		b = block(plaintext=new_p, vector=b"abcdefghijk")
		old_p = b.paddingANSIX923(inverse=True)
		self.assertEqual(old_p,b"abcd")

		# plaintext size > block size
		b = block(plaintext=b"abcdefghijk", vector=b"abcd")
		new_p = b.paddingANSIX923()
		self.assertNotEqual(len(new_p) - len(b"abcd"), -1)
		self.assertEqual(len(new_p) % len(b"abcd"), 0)

		b = block(plaintext=new_p, vector=b"abcd")
		old_p = b.paddingANSIX923(inverse=True)
		self.assertEqual(old_p, b"abcdefghijk")

		# plaintext size = block size

		b = block(plaintext=b"efgh", vector=b"abcd")
		new_p = b.paddingANSIX923()
		self.assertNotEqual(len(new_p) - len(b"abcd"), -1)
		self.assertEqual(len(new_p) % len(b"abcd"), 0)

		b = block(plaintext=new_p, vector=b"abcd")
		old_p = b.paddingANSIX923(inverse=True)
		self.assertEqual(old_p, b"efgh")

	def test_paddingISOIEC7816_4(self):

		# plaintext size < block size
		b = block(plaintext=b"abcd", vector=b"abcdefghijk")
		new_p = b.paddingISOIEC7816_4()
		self.assertNotEqual(len(new_p) - len(b"abcdefghijk"), -1)
		self.assertEqual(len(new_p) % len(b"abcdefghijk"), 0)

		b = block(plaintext=new_p, vector=b"abcdefghijk")
		old_p = b.paddingISOIEC7816_4(inverse=True)
		self.assertEqual(old_p,b"abcd")
		
		# plaintext size > block size
		b = block(plaintext=b"abcdefghijk", vector=b"abcd")
		new_p = b.paddingISOIEC7816_4()
		self.assertNotEqual(len(new_p) - len(b"abcd"), -1)
		self.assertEqual(len(new_p) % len(b"abcd"), 0)

		b = block(plaintext=new_p, vector=b"abcd")
		old_p = b.paddingISOIEC7816_4(inverse=True)
		self.assertEqual(old_p, b"abcdefghijk")

		# plaintext size = block size
		b = block(plaintext=b"efgh", vector=b"abcd")
		new_p = b.paddingISOIEC7816_4()
		self.assertNotEqual(len(new_p) - len(b"abcd"), -1)
		self.assertEqual(len(new_p) % len(b"abcd"), 0)

		b = block(plaintext=new_p, vector=b"abcd")
		old_p = b.paddingISOIEC7816_4(inverse=True)
		self.assertEqual(old_p, b"efgh")

	def test_paddingxff(self):

		# plaintext size < block size
		b = block(plaintext=b"abcd", vector=b"abcdefghijk")
		new_p = b.paddingxff()
		self.assertNotEqual(len(new_p) - len(b"abcdefghijk"), -1)
		self.assertEqual(len(new_p) % len(b"abcdefghijk"), 0)

		b = block(plaintext=new_p, vector=b"abcdefghijk")
		old_p = b.paddingxff(inverse=True)
		self.assertEqual(old_p,b"abcd")

		# plaintext size > block size
		b = block(plaintext=b"abcdefghijk", vector=b"abcd")
		new_p = b.paddingxff()
		self.assertNotEqual(len(new_p) - len(b"abcd"), -1)
		self.assertEqual(len(new_p) % len(b"abcd"), 0)

		b = block(plaintext=new_p, vector=b"abcd")
		old_p = b.paddingxff(inverse=True)
		self.assertEqual(old_p, b"abcdefghijk")
		# plaintext size = block size

		b = block(plaintext=b"efgh", vector=b"abcd")
		new_p = b.paddingxff()
		self.assertNotEqual(len(new_p) - len(b"abcd"), -1)
		self.assertEqual(len(new_p) % len(b"abcd"), 0)

		b = block(plaintext=new_p, vector=b"abcd")
		old_p = b.paddingxff(inverse=True)
		self.assertEqual(old_p, b"efgh")

if __name__ == '__main__':

	unittest.main()