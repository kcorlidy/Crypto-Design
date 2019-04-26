from binascii import unhexlify, hexlify
import unittest
import re
import warnings
from _warn import ParamWarning, ParamError
from Operator_ import Xor, Add, Sub, Mul, Mod

class Lai_Massey(object):
	
	def __init__(self, key, rounds, f=None, h=None, h_=None):
		self.key = key
		self.rounds = rounds
		self.F = f if f else self.F_
		self.H = h if h else self.H
		self.H_ = h_ if h_ else self.H_
		self.checkit(key)

	
	def checkit(self,key):
		if self.F != self.F_:
			warnings.warn("You are using self-define F function, which have to return a binary string", ParamWarning,stacklevel=2)
		if len(key)%2 != 0:
			raise ParamError("Invalid key length")

	def F_(self, a, key):
		"""
		F should return a relative size result, which equals to L and R, 
			otherwise we can't decrypt correctly. 
		Because the ciphertext will be extended if return a bigger number.
		"""
		p = Xor(key, a)
		return p


	def H(self,L,R):
		# exchange
		return R,L

	def H_(self,L,R):
		return R,L
		

	def encrypt(self,plaintext):
		if len(self.key) < len(plaintext):
			raise RuntimeError("Key size must be longer than plaintext size")
		if len(plaintext)%2 != 0:
			raise RuntimeError

		lens = int(len(plaintext)/2)
		L, R= plaintext[:lens], plaintext[lens:]
		
		L_, R_ = self.H(L, R)
		
		for _ in range(self.rounds):
			x = Sub(L_, R_)[:lens-1] # ensure the text will not be extended
			k = x if x else b"\x00"
			T = self.F(k, self.key)
			L_, R_ = self.H( Add(L_, T), Add(R_, T))
			
		return  L_ + R_

	def decrypt(self,ciphertext):
		lens = int(len(ciphertext)/2)
		L, R = ciphertext[:lens], ciphertext[lens:]
		
		L_, R_ = self.H(L, R)
		
		for _ in range(self.rounds):
			x = Sub(L_, R_)[:lens-1] 
			k = x if x else b"\x00"
			T = self.F(k, self.key)
			L_, R_ = self.H( Sub(L_, T), Sub(R_, T))
			
		return L_ + R_


class test(unittest.TestCase):
	
	def test_base(self):
		key = b"ADAW2FS4242fdawdawdawdadad"
		plaintext = b"abcd"

		f = Lai_Massey(key,2)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)

	def test_different_types_string(self):
		key = b'\xff'*16
		plaintext = b"abcdfe"
		# integer too big the text will be extending, have to fixed it.
		f = Lai_Massey(key,1)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)

	def test_strange_inpt1(self):
		key = b"abcdfe"
		plaintext = b"abcdfe"

		f = Lai_Massey(key,2)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)

	def test_strange_inpt2(self):
		key = b'\x00'*16
		plaintext = b'\xe4Q`\xdb!F\x0c\xfb\xbdZ\xb8?&%A\xf2'

		f = Lai_Massey(key,2)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)
		self.assertEqual(plaintext,plaintext_)

	def test_strange_inpt3(self):
		key = b'\xff'*16
		plaintext = b'\xfc'*8

		f = Lai_Massey(key,2)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)
		self.assertEqual(plaintext,plaintext_)

	
if __name__ == '__main__':

	unittest.main()