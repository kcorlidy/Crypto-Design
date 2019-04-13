from binascii import unhexlify, hexlify
import unittest
import re
from itertools import product
from copy import copy
from functools import reduce
"""
Just a very very simple of S-box. Dont use it anywhere! But it is a dynamic S-Box.
	1.I will create a S-Box that input size equals to output size.
	2.If you define you own `bent function`, so you have to define the opposite one.
"""

class S_box(object):
	""" 
	[0000, 1111] = [0, 15] = [0, F]
	"""

	def __init__(self, *, bent_func=None, inverse_func=None):
		self.bent_func = bent_func if bent_func else self._bent_func
		self.inverse_func = inverse_func if inverse_func else self._inverse_func

	def _bent_func(self,r,c):
		# row, column, plaintext(self.p) will decide what it output
		p = [int(format(ord(x), '#010b'), 2) for x in self.plaintext]
		p = reduce(lambda x,y: x^y, p) # ((a0 ^ a1) ^ a3)^...)^an
		number = r + 2*c
		while number > 255:
			number -= 255
		return format(p ^ number, '#010b')[2:]

	def initialize(self):
		n = 16
		box = [[0] * n for _ in range(n)] # 16 * 16
		_func = self.bent_func if self.plaintext else self._inverse_func
		for couple in product(r"0123456789ABCDEF", repeat=2):
			r,c = int(couple[0], 16), int(couple[1], 16)
			box[r][c] = _func(r,c)

		return box

	def _inverse_func(self,r,c):
		# row, column, ciphertext(self.c) will decide what it output
		
		# honestly, i can create the inverse bent function, or inverse S-Box. It is too tough.
		ci = format(self.ciphertext, '#010b')[2:]
		while len(ci)%8:
			ci = "0" + ci

		ci = [int(ele, 2) for ele in re.findall(r"\d{8}" , ci)]
		
		ci = reduce(lambda x,y: x^y, ci) # ((a0 ^ a1) ^ a3)^...)^an
		number = r + 2*c
		while number > 255:
			number -= 255
		return format(ci ^ number, '#010b')[2:]

	def select(self,plaintext=None ,ciphertext=None):
		if not plaintext and not ciphertext:
			raise AttributeError("plaintext or ciphertext is necessary.")
		elif plaintext and ciphertext:
			raise AttributeError("plaintext or ciphertext is necessary. But only one we need!")

		self.plaintext = plaintext
		self.ciphertext = int(ciphertext, 16) if ciphertext else None

		value = plaintext if plaintext else self.ciphertext
		# 8bits each, and divide into two parts
		box = self.initialize()
		
		if self.plaintext:
			to_bin = [re.findall(r"\d{4}" ,format(ord(x), '#010b')[2:]) for x in value] 
			ciphertext = "".join([box[int(a, 2)][int(b,2)] for a,b in to_bin])
			return hex(int(ciphertext, 2))[2:]

		elif self.ciphertext:
			return box #[box[int(a, 2)][int(b,2)]]

class test(unittest.TestCase):

	def test_base(self):
		box = S_box()
		plaintext = "awdc"
		output = box.select(plaintext=plaintext)
		inputs = [format(ord(x), '#010b')[2:] for x in plaintext]
		print(inputs,"inputs")
		print(output)

		# if output equals to input
		self.assertNotEqual(inputs, output)
		self.assertEqual(True if len(set(inputs) - set(output)) >= 3 else False , True)
		rbox = box.select(ciphertext=output)
		

if __name__ == '__main__':

	unittest.main()