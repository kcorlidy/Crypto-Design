from binascii import unhexlify, hexlify
import unittest
import re
import warnings
from operator import xor
import textwrap
from functools import reduce
import sys

class Mode(object):

	def __init__(self, key, encrypt, decrypt , _rounds=6, **kw):
		self.IV = self.toint(kw.get("IV"))
		self.counter = kw.get("counter")
		self.key = key

		# Be reuseable, through applying function instead of embedding all class into a cipher.
		self._encrypt = encrypt
		self._decrypt = decrypt

		self._rounds = _rounds
		self.plaintext = kw.get("plaintext")
		self.ciphertext = kw.get("ciphertext")

	def toint(self,value):
		
		return int(self.tobin(value).replace(" ",""), 2)

	def tobin(self,value,binstring=False):
		try:
			return ' '.join(format(ord(x), '#010b')[2:] for x in value)
		except Exception as e:
			try:
				return ' '.join(format(x, '#010b')[2:] for x in value)
			except Exception as e:
				b = ''.join(format(value, '#010b')[2:])
				while len(b)%8:
					b = "0" + b
				if not binstring:
					return [int(s, 2) for s in re.findall(r"\d{8}",b)]
				return b

	def tointarray(self,value):
		return [int(x, 2) for x in self.tobin(value).split()]

	@property
	def digest(self):
		return bytes(
				self.tobin(self.ciphertext))

	@property
	def hexdigest(self):
		return hexlify(self.digest)

	def b2s(self,bins):
		return bytes([ int(ele,2) for ele in re.findall(r"\d{8}",bins)])

class ECB(Mode):
	
	def encrypt(self,p):

		output = []
		for p_ in p:
			output += [self._encrypt(p_)]

		return output

	def decrypt(self,c):

		output = []
		for c_ in c:
			output += [self._decrypt(c_)]

		return self.b2s(self.tobin(output))

class CBC(Mode):

	def encrypt(self,p):
		"""
		Ci = Ek(Pi xor Ci-1)
		C0 = IV
		"""
		output = []
		IV = self.IV
		for _,p_ in enumerate(p):
			out = self._encrypt(p_ ^ IV)
			output += [out]
			IV = out
		return output

	def decrypt(self,c):
		"""
		Pi = Dk(Ci) xor Ci-1
		C0 = IV
		"""
		output = []
		IV = self.IV
		for _,c_ in enumerate(c):
			out = self._decrypt(c_) ^ IV
			output += [out]
			IV =  c_
		return self.b2s(self.tobin(output))

class PCBC(Mode):
	# size of IV alawys bigger than px
	def encrypt(self,p):
		IV = self.IV
		arr = []
		for px in p:
			state = px ^ IV
			state = self._encrypt(state)
			IV = state ^ px
			#px = state
			arr += [state]
		string = reduce(lambda x,y: x+y ,[r.to_bytes(8, sys.byteorder) for r in arr])
		#print(arr,"arr", hexlify(string))# bytearray.fromhex('{:01x}'.format(r))
		self.ciphertext = state 
		#print(self.decrypt(arr))
		return arr

	def decrypt(self,c):
		#print(c,"cx")
		IV = self.IV
		arr = []
		for cx in c:
			state = self._decrypt(cx)
			state = state ^ IV
			IV = cx ^ state
			arr += [state]
		return self.b2s(self.tobin(arr))

class CFB(Mode):

	def encrypt(self,p):
		# Ci = Ek(C_{i-1}) xor Pi
		P0 = self.toint(p)
		C = [self.IV]
		P = [0,P0]
		for _ in range(1, self._rounds):
			C.append(self._encrypt(C[_-1]) ^ P[_])
			P.append(C[-1])
		self.ciphertext = C[-1]
		print(C,P0)
		return self

	def decrypt(self,c):
		# Pi = Ek(C_{i-1}) xor Ci
		Ciphertext = int(c ,16)
		P = [self.IV, Ciphertext]

		for _ in range(1, self._rounds):
			P.append(self._encrypt(P[_-1]) ^ P[_])

		print(P)
		return self.b2s(self.tobin(P[-1], binstring=True))

class OFB(Mode):

	def encrypt(self,p):
		pass

	def decrypt(self,c):
		pass

class CTR(Mode):

	def encrypt(self,p):
		pass

	def decrypt(self,c):
		pass

class XEX(Mode):
	# https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS
	def encrypt(self,p):
		pass

	def decrypt(self,c):
		pass



class test(unittest.TestCase):

	def test_ECB(self):
		mode = ECB(key=b"awdad",encrypt=lambda x: x + 3,decrypt=lambda x: x - 3, _rounds=7,IV=b"abcd")
		cipher = mode.encrypt(b"efgh")
		plain  = mode.decrypt(cipher)
		self.assertEqual(b"efgh", plain)
	
	def test_CBC(self):
		mode = CBC(key=b"awdad",encrypt=lambda x: x + 3,decrypt=lambda x: x - 3, _rounds=7,IV=b"abcd")
		cipher = mode.encrypt(b"efgh")
		plain  = mode.decrypt(cipher)
		self.assertEqual(b"efgh", plain)

	def test_PCBC(self):
		mode = PCBC(key=b"awdad",encrypt=lambda x: x + 9,decrypt=lambda x: x - 9, _rounds=6,IV=b"abcdefgh")
		cipher = mode.encrypt(b"efghfg")
		plain = mode.decrypt(cipher)
		self.assertEqual(b"efghfg",plain)

	def _test_CFB(self):
		func0 = lambda x: x + 440
		mode = CFB(key=b"awdad",encrypt=func0,decrypt=func0, _rounds=8,IV=b"abcd")
		cipher = mode.encrypt(b"efgh")
		c = cipher.hexdigest
		mode.decrypt(c)
		#self.assertEqual(b"efgh",mode.decrypt(c))
	
if __name__ == '__main__':

	unittest.main()	