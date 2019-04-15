from binascii import unhexlify, hexlify
import unittest
import re
from itertools import product
from copy import copy
from functools import reduce
import warnings

"""
Just a very very simple of S-box. Dont use it anywhere! But it is a dynamic S-Box.
	1.I will create a S-Box that input size equals to output size.
	2.If you define you own `bent function`, so you have to define the opposite one.
"""

class S_box(object):
	""" 
	[0000, 1111] = [0, 15] = [0, F]
	"""

	def __init__(self, key, *, bent_func=None, inverse_func=None, rounds=6):
		self.bent_func = bent_func if bent_func else self._bent_func
		self.inverse_func = inverse_func if inverse_func else self._inverse_func
		self.box_num = int(len(key)/16)

		if len(key)%8 != 0:
			warnings.warn("Key size should be multiple of sixteen, otherwise the rest part will be abandoned", stacklevel=1)
			
		self.key = self.tobin(key)
		self.store = dict() # save the data that always uses and does not modify.
		self.unique = set()
		self.box = self.inverse_box = {}
		self.rounds = rounds
		self.initialize()

	def tobin(self,value):
		try:
			return ' '.join(format(ord(x), '#010b')[2:] for x in value) # 8bit is necessary.
		except Exception as e:
			return ' '.join(format(x, '#010b')[2:] for x in value)

	def get8bin(self,value):
		try:
			return re.findall(r"\d{8}", value)[0]
		except Exception as e:
			return re.findall(r"\d{8}", value.replace("b",""))[0]
		

	def _bent_func(self,r,c):
		"""
		row, column, plaintext(self.p) will decide what it will output
		It will be a awful bent function if used `reduce(lambda x,y: x^y, p)`
		Because the real length of key is 8 instead of 8n
		We must limit that key length % 16 == 0, so we can apply each 8bits to each row/column.row
		If key size is 32 so we can build two S-boxes. 48 to 3, 64 to 4.
		`task above has finished`

		2019-04-14 21:28:36, i think we have to make the output be more chaos.
		"""

		p = self.store.get("p")

		if not self.store.get("_p"):
			_p = reduce(lambda x,y: x^y, p) # ((a0 ^ a1) ^ a3)^...)^an
			self.store["_p"] = _p
		else:
			_p = self.store.get("_p")

		p = p[c]

		number = r**4 + r*(c**3) - r*3
		# Ensure the result is unique element in the S-Box
		result = self.get8bin(format(p ^ number, '#010b'))

		while not set([result]) - self.unique:
			if number > 255:
				number -= 255
			number += 1
			result = self.get8bin(format(p ^ number, '#010b'))

		self.unique.add(result)

		return result

	def initialize(self):
		"""
		Create a box, by using key, plaintext, ciphertext.
		But i chose key only,
			 using plaintext or ciphertext have to take very long time to build the relationship between S-box and inverse S-box.
		Be careful, each element have to be unique, otherwise inverse-box may become useless.
		"""

		# initialize fundamental parameter that need in bent function.
		n = 16
		self.store["p"] = [int(k, 2) for k in self.key.split()]

		for _ in range(self.box_num):
			self.box[_] = self.inverse_box[_] = [[0] * n for _ in range(n)] # 16 * 16
			for couple in product(r"0123456789ABCDEF", repeat=2):

				r,c = int(couple[0], 16), int(couple[1], 16)

				self.box[_][r][c] = self.bent_func(r,c)

				if self.inverse_func != self._inverse_func:
					self.inverse_box[_][r][c] = self.inverse_func(r,c)

			# re-initialize, preparing for the next S-Box.
			self.unique = set()
			self.store["p"] = self.store["p"][16*(_+1):]

		
	def _inverse_func(self,r,c):
		
		return None

	def _inverse_box(self,value):
		"""
		honestly, i can't create the inverse bent function, 
			but i can build a inverse S-Box.
		"""
		try:
			return list(zip(*np.where(self.box.get(0) == value)))[0]

		except Exception as e:
			
			return [(ix,iy) for ix, row in enumerate(self.box.get(0)) for iy, i in enumerate(row) if i == value][0]
		

	def select(self,plaintext=None ,ciphertext=None):

		if not plaintext and not ciphertext:
			raise AttributeError("plaintext or ciphertext is necessary.")
		elif plaintext and ciphertext:
			raise AttributeError("plaintext or ciphertext is necessary. But only one we need!")

		self.plaintext = self.tobin(plaintext) if plaintext else None
		self.ciphertext = int(ciphertext, 16) if ciphertext else None


		if self.plaintext:
			for _ in range(self.rounds):
				to_bin_set = [re.findall(r"\d{4}" , x) for x in self.plaintext.split()]
				self.plaintext = " ".join([self.box.get(0)[int(a, 2)][int(b,2)] for a,b in to_bin_set])
			return hex(int(self.plaintext.replace(" ", ""), 2))[2:]

		elif self.ciphertext:
			cipherbin = format(self.ciphertext, "#010b")[2:]
			while len(cipherbin)%8:
				cipherbin = "0" + cipherbin

			for _ in range(self.rounds):
				bins = re.findall(r"\d{8}", cipherbin)
				pos = [self._inverse_box(b) for b in bins]
				result = [format(a,"#06b")[2:]+format(b,"#06b")[2:] for a,b in pos]

				if _ != self.rounds:
					cipherbin = "".join(result)
			
			return bytes([int(r, 2) for r in result])
	
	


class test(unittest.TestCase):

	def test_base(self):
		box = S_box(b"thithisdawdenbyteswdawdawddawda3232d",rounds=6)
		plaintext = b"tbuytawewrtecees"
		output = box.select(plaintext=plaintext)
		rbox = box.select(ciphertext=output)
		self.assertEqual(plaintext, rbox)
		print(output)
		
		

if __name__ == '__main__':
	"""
	The shortcome of S-box is one to one relationship. One input to another fixed output.
	So i think multiple S-Box is necessary, 2 or more can make output look more complicated.
	"""
	unittest.main()