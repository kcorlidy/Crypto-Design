from binascii import unhexlify, hexlify
import unittest
import re
import warnings
from operator import xor
import hashlib
import sys
import os

from _block import block

class Mode(object):

	def __init__(self, encrypt, decrypt, mode, block_size=16, **kw):
		self.IV = kw.get("IV")
		self.block_size = block_size
		self.counter = kw.get("counter")
		self.mode = [ECB, CBC, PCBC , CFB, CFBm, OFB, CTRm][mode]

		# Be reuseable, through applying function instead of embedding all class into a cipher.
		self._encrypt = encrypt
		self._decrypt = decrypt

		self.ciphertext = None

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

	def head(self,s):
		return int(s/(10**self.x))

	def _counter(self,count):
		# create fixed size nonce and counter. 16bytes = 64bits
		result = self.toint((hashlib.sha512(self._iv + bytes(count)).digest())[:self.block_size])
		return result

	@property
	def digest(self):
		return b"".join(c for c in self.ciphertext)

	@property
	def hexdigest(self):
		return b"".join(hexlify(c) for c in self.ciphertext)

	def to_bytes(self,array):
		bins = map(self.tobin, array)
		byte = lambda bins: bytes([int(ele,2) for ele in re.findall(r"\d{8}",bins)])
		return b"".join(map(byte, bins))

	def xor_bytes(self,a,b):
		return b"".join( [ints.to_bytes(1, sys.byteorder) for ints in map(lambda x: xor(*x), zip(a,b))] )

	def encrypt(self, p):
		if self.mode in [ECB, CBC]:
			p = block(plaintext=p, block_size=self.block_size, padding="xff")._block
		else:
			p =  block(plaintext=p, block_size=self.block_size)._block

		return self.mode.encrypt(self, p)

	def decrypt(self, c):
		c = block(ciphertext=c, block_size=self.block_size)._block
		output = b"".join(self.mode.decrypt(self, c))
		
		if self.mode in [ECB, CBC]:
			return self.to_bytes(
				block(plaintext=output, block_size=self.block_size,
				 padding="xff", inverse=True)._block)
		else:
			return self.to_bytes(
				block(ciphertext=output, block_size=self.block_size)._block)
	

class ECB(Mode):

	def encrypt(self,p):

		output = map(self._encrypt, p)
		self.ciphertext = list(output)
		return self

	def decrypt(self,c):
		
		output = map(self._decrypt, c)
		return list(output)

class CBC(Mode):

	def encrypt(self,p):
		"""
		Ci = Ek(Pi xor Ci-1)
		C0 = IV
		"""
		output = []
		IV = self.IV
		for _,p_ in enumerate(p):
			out = self._encrypt( self.xor_bytes(p_, IV) )
			output += [out]
			IV = out
		
		self.ciphertext = output
		return self

	def decrypt(self,c):
		"""
		Pi = Dk(Ci) xor Ci-1
		C0 = IV
		"""
		output = map(lambda tup: self.xor_bytes(self._decrypt(tup[0]), tup[1]), zip(c, [self.IV] + c[:-1]))

		return list(output)

class PCBC(Mode):

	def encrypt(self,p):

		IV = self.IV
		output = []
		for px in p:
			state = px ^ IV
			state = self._encrypt(state)
			IV = state ^ px
			#px = state
			output += [state]

		self.ciphertext = output[0]
		return self

	def decrypt(self,c):
		
		IV = self.IV
		output = []
		for cx in c:
			state = self._decrypt(cx)
			state = state ^ IV
			IV = cx ^ state
			output += [state]

		return output

class CFB(Mode):

	def encrypt(self,p):
		# Ci = Ek(C_{i-1}) xor Pi
		IV = self.IV
		output = []
		for px in p:
			state = self._encrypt(IV) ^ px
			IV = state
			output += [state]

		self.ciphertext = self.to_bytes(output)
		return self

	def decrypt(self,c):
		# Pi = Ek(C_{i-1}) xor Ci
		output = map(lambda tup: self._encrypt(tup[0]) ^ tup[1], zip([self.IV] + c[:-1], c))
		return output

class CFBm(Mode):
	# CFB modified version

	def encrypt(self,p):
	
		
		self.x = 8
		S = self.IV
		n = len(str(self.IV))
		output = []
		for px in p:
			state = self.head(self._encrypt(S)) ^ px
			S = ((S << self.x) + state) % (2**n)
			output += [state]
		
		self.ciphertext = self.to_bytes(output)

		

		return self

	def decrypt(self,c):

		self.x = 8
		S = self.IV
		n = len(str(self.IV))
		output = []
		for cx in c:
			state = self.head(self._encrypt(S)) ^ cx
			S = ((S << self.x) + state) % (2**n)
			output += [state]

		return output

		

class OFB(Mode):
	"""
	Oj = Ek(Ij)
	Ij = O_{j-1}
	I0 = IV
	Cj = Pj xor Oj
	Pj = Cj xor Oj
	"""
	def encrypt(self,p):

		IV = self.IV
		output = []
		for px in p:
			o = self._encrypt(IV)
			output += [px ^ o]
			IV = o
		
		self.ciphertext = self.to_bytes(output)
		return self

	def decrypt(self,c):

		IV = self.IV
		output = []
		for cx in c:
			o = self._encrypt(IV)
			output += [cx ^ o]
			IV = o
		return output

class CTRm(Mode):
	"""
	A modified version of CTR. Ordinary CTR have to input counter function, 
		but CTRm(CTR modified) can change IV to a Nonce.
	"""

	def encrypt(self,p):

		output = map(lambda tup: self._encrypt(self._counter(tup[0])) ^ tup[1], enumerate(p))
		self.ciphertext = self.to_bytes(output)
		return self

	def decrypt(self,c):

		output = map(lambda tup: self._encrypt(self._counter(tup[0])) ^ tup[1], enumerate(c))
		return output

class XTS(Mode):
	# https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS
	"""
	P is the plaintext,
	i is the number of the sector,
	alpha  is the primitive element of GF(2^{128}) defined by polynomial x; i.e., the number 2,
	j is the number of the block within the sector.
	"""
	def encrypt(self,p):
		raise NotImplementedError

	def decrypt(self,c):
		raise NotImplementedError



class test(unittest.TestCase):
	"""
	Divide plaintext/ciphertext into block(s), then start doing. 
	Why need block? We can know how long plaintext is. 
		Or said we dont care how long plaintext is, we just need to compute the block(s) then result come out
	"""

	def test_all(self):
		key = None
		mode = range(7) # [ECB, CBC, PCBC , CFB, CFBm, OFB, CTRm]
		IV = [b"\xff"*16, b"\x00"*16, b"\x00abdcjioadwwefr"]
		plaintext = [b"\xfe"*15, b"\x02"*15, b"\x01abdcjioadwwefr"]
		for class_ in mode:
			print(class_)
			for p in plaintext:
				for iv in IV:
					mode = Mode(key=key,encrypt=lambda x: x, decrypt=lambda x: x, mode=class_, IV=iv)
					cipher = mode.encrypt(p)
					plain = mode.decrypt(cipher.hexdigest)
					self.assertEqual(p,plain)

	def _test_special_content(self):
		# byte xored byte, bit xored bit, not block to int then xored
		# so how to ensure the plaintext which size 1 can output a full block content after xored.
		key = None
		mode = range(7) # [ECB, CBC, PCBC , CFB, CFBm, OFB, CTRm]
		IV = [b"\xff"*16, b"\x00"*16, b"\x00abdcjioadwwefr"]
		plaintext = [b"\x00"*15, b"\xff"*15, b"\x01abdcjioadwwefr"]
		for class_ in mode:
			for p in plaintext:
				for iv in IV:
					mode = Mode(key=key,encrypt=lambda x: x ^ 9, decrypt=lambda x: x ^ 9, mode=class_, IV=iv)
					cipher = mode.encrypt(p)
					print(len(cipher.hexdigest), class_)
					plain = mode.decrypt(cipher.hexdigest)
					self.assertEqual(p,plain)
		
if __name__ == '__main__':

	unittest.main()	