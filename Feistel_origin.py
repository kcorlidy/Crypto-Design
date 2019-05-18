from binascii import unhexlify, hexlify
import unittest
import re
import warnings
from _warn import ParamWarning, ParamError
from Crypto import Random
from Operator_ import Xor
import sys
import os

class Feistel(object):
	
	def __init__(self, key, rounds, f=None):
		self.key = key
		self.rounds = rounds
		self.F = f if f else Feistel.F
		self.checkit(key)

	
	def checkit(self,key):
		if self.F != Feistel.F:
			warnings.warn("You are using self-define F function, which have to return a binary string", ParamWarning,stacklevel=2)
		if len(key)%2 != 0:
			raise ParamError("Invalid key length")

	def F(self,a,key):
		# a,key are integer.
		return Xor(a,key)

	def encrypt(self,plaintext):

		if len(plaintext)%2 != 0:
			raise RuntimeError("This is balanced Feistel")

		if len(plaintext) > len(self.key):
			raise RuntimeError("key size have to larger than block size")

		lens = int(len(plaintext)/2)
		L = [plaintext[:lens]]
		R = [plaintext[lens:]]

		for _ in range(self.rounds):	
			L += [R[_]]
			R += [Xor(L[_], 
			self.F(self, R[_], self.key)
			)]
		
		return  L[-1] + R[-1]

	def decrypt(self,ciphertext):
		lens = int(len(ciphertext)/2)
		L = [None]*self.rounds + [ciphertext[:lens]]
		R = [None]*self.rounds + [ciphertext[lens:]]
		
		for _ in range(self.rounds)[::-1]:
			R[_] = L[_+1]
			L[_] = Xor(R[_+1], 
						self.F(self,L[_+1], self.key)
									)
		
		return L[0]+R[0]


class test(unittest.TestCase):
	
	def test_base(self):
		key = b"1234"
		plaintext = b"\x00\x00"

		f = Feistel(key,3)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)
		print(ciphertext, plaintext_)
		self.assertEqual(plaintext,plaintext_)
	
	def test_new_F(self):
		key = b"123433"
		plaintext = b"abcdfg"

		def _f(self, a, key):
			return Xor(Xor(a,key), b"\xff"*16)

		f = Feistel(key,3,f=_f)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)

	def test_different_types_string(self):
		key = b'\xe4Q`\xdb!F\x0c\xfb\xbdZ\xb8?&%A\xf2'
		plaintext = b"abcdfg"

		f = Feistel(key,3)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)

	def test_strange_inpt1(self):
		key = b"12#A333213"
		plaintext = b"@!#CASF:"

		f = Feistel(key,3)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)
	
	def test_strange_inpt2(self):
		key = b'\xe4Q`\xdb!F\x0c\xfb\xbdZ\xb8?&%A\xf2'
		plaintext = b'\xe4Q`\xdb!F\x0c\xfb\xbdZ\xb8?&%A\xf2'

		f = Feistel(key,3)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)
		#plaintext_ = unhexlify(plaintext_) # need to do it by yourself.
		self.assertEqual(plaintext,plaintext_)
	
	def test_strange_inpt3(self):
		for _ in range(10):
			key = Random.new().read(160)
			plaintext = Random.new().read(80)

			f = Feistel(key,50)
			ciphertext = f.encrypt(plaintext)
			plaintext_ = f.decrypt(ciphertext)
			self.assertEqual(plaintext,plaintext_)
	
if __name__ == '__main__':

	unittest.main()