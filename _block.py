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
	def __init__(self, block_size, plaintext=None, ciphertext=None, 
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



	"""
	block extending is not available, but i will keep it because i think i will use it again.
	"""
	def remove_extending(self):
		# there is something wrong about re.sub, so i have to change to this.
		self.plaintext = self.plaintext.replace(
			b"".join(re.findall(b"\xff\xff.*\xff\xff",  self.plaintext, re.DOTALL)), b"")


	def block_extend(self, blocks):
		"""
		_num:	 		how many block(s) we need
		"""
		origin = blocks
		x = len(origin)
		_num = 0
		func = lambda n : int(64*n/self.block_size - x)
		for n in range(1,1000):
			_num = func(n)
			if _num > 0:
				_num = int(_num)
				break

		 
		extending_block = [b"\xff\xff"+ byte +b"\xff\xff" for byte in self.to_14bytes(_num)]
		return origin + extending_block

	def to_14bytes(self, _num):
		"""
		use plainext and number to compute the seed, key is option
		p -> plaintext to int

		p' -> p^n * e^n + key^3 n->[0,k1]
		   -> p^n * pi^n + key^3 n->[k1,infinity]
		   n -> how many block we need
		   ki -> 64/block_size
			  -> 64/16 [0,2] (2,4] Recommend
			  -> 64/8  [0,4] (4,8] Option
			  -> 64/32 [0,1] (1,2] Not recommend, if block_size bigger than 32, raise error.

		"""

		if _num <= (64/self.block_size)/2:
			seeds = int(self.toint(self.plaintext) ** _num) * int((3**0.7) **_num)
		else:
			seeds = int(self.toint(self.plaintext) ** _num) * int((7**0.3) **_num)

		seed(seeds)
		return [b"".join([randint(1,254).to_bytes(1, sys.byteorder) for _ in range(self.block_size - 4)]) for _ in range(_num)]


class test(unittest.TestCase):

	def test_padding(self):
		func = ["PKCS7", "ISO10126", "xff", "ANSIX923", "ISOIEC7816_4"]
		for f in func:
			print(f)
			# plaintext size < block size
			b = block(plaintext=b"abcd", block_size=b"efghijkl")
			new_p = b.blocks(padding=f)._block
			self.assertNotEqual(len(new_p[0]) - len(b"efghijkl"), -1)
			self.assertEqual(len(new_p[0]) % len(b"efghijkl"), 0)

			new_p = b"".join(new_p)
			b = block(plaintext=new_p, block_size=b"efghijkl", extending=0)
			old_p = b.blocks(padding=f, inverse=True)._block
			self.assertEqual(b"".join(old_p), b"abcd")
			
			# plaintext size > block size
			b = block(plaintext=b"abcdefghijk", block_size=b"abcdefgh")
			new_p = b.blocks(padding=f)._block
			self.assertNotEqual(len(new_p[0]) - len(b"abcdefgh"), -1)
			self.assertEqual(len(new_p[0]) % len(b"abcdefgh"), 0)

			new_p = b"".join(new_p)
			b = block(plaintext=new_p, block_size=b"abcdefgh", extending=0)
			old_p = b.blocks(padding=f, inverse=True)._block
			self.assertEqual(b"".join(old_p), b"abcdefghijk")

			# plaintext size = block size
			b = block(plaintext=b"abcdefgh", block_size=b"abcdefgh")
			new_p = b.blocks(padding=f)._block
			self.assertNotEqual(len(new_p[0]) - len(b"abcdefgh"), -1)
			self.assertEqual(len(new_p[0]) % len(b"abcdefgh"), 0)

			new_p = b"".join(new_p)
			b = block(plaintext=new_p, block_size=b"abcdefgh", extending=0)
			old_p = b.blocks(padding=f, inverse=True)._block
			self.assertEqual(b"".join(old_p), b"abcdefgh")

	def test_block_extending(self):
		#b = block(plaintext=b"efgh", block_size=8)
		pass

if __name__ == '__main__':

	unittest.main()