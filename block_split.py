from binascii import unhexlify, hexlify
import unittest
import re
import warnings
from operator import xor
import textwrap
from functools import reduce
import sys
import hashlib


class block(object):
	"""
	vector can be `key` or `IV`
	"""
	def __init__(self, plaintext, vector):
		self.block_size = len(vector)
		self.plaintext = plaintext
		self.plaintext_size = len(plaintext)


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

	def test_blcok(self):
		b = block(plaintext=b"1234", vector=b"a3").blocks
		

	def test_blcok2(self):
		b = block(plaintext=b"1", vector=b"a3").blocks
		

	def test_blcok3(self):
		b = block(plaintext=b"1", vector=b"a3").blocks_int
		

	def test_blcok3(self):
		b = block(plaintext=b"131231", vector=b"a3").blocks_int
		print(list(b))

if __name__ == '__main__':

	unittest.main()