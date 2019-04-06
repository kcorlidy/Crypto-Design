from binascii import a2b_hex, b2a_hex, unhexlify, hexlify
import unittest
import re
import warnings
from _warn import ParamWarning, ParamError
from Crypto import Random

class Feistel(object):
	"""docstring for Fi"""
	def __init__(self, key, rounds, f=None):
		self.key = self.all2bin(key)
		self.rounds = rounds
		self.F = f if f else Feistel.F
		self.checkit(key)

	
	def checkit(self,key):
		if self.F != Feistel.F:
			warnings.warn("You are using self-define F function, which have to return a binary string", ParamWarning,stacklevel=2)
		if len(key)%2 != 0:
			raise ParamError("Invalid key length")

	def all2bin(self,value):
		try:
			return ''.join(format(ord(x), '#010b')[2:] for x in value) # 8bit is necessary.
		except Exception as e:
			pass

		try:
			return self.all2bin(hexlify(value).decode())
		except Exception as e:
			pass

		raise ParamError("Can't decode your input.")

	def b2i(self,a,key):
		# i think i should make key can only be integer or binary.
		# binary to integer
		return int(a, 2), int(key, 2)

	def F(a,key):
		return bin(a * key)[2:]

	def zip_(self,first,second):
		return zip(list(first),
			list(
				self.F(
					*self.b2i(second, self.key)
					)
				)
			)

	def encrypt(self,plaintext):
		lens = int(len(plaintext)/2)
		L = [self.all2bin(plaintext[:lens])]
		R = [self.all2bin(plaintext[lens:])]

		for _ in range(self.rounds):	
			L += [R[_]]
			R += ["".join([str(int(a)^int(b)) for a,b in self.zip_(L[_],R[_]) ])]
				
		return L[-1],R[-1]

	def decrypt(self,Ln,Rn):
		L = [None]*self.rounds + [Ln]
		R = [None]*self.rounds + [Rn]
		for _ in range(self.rounds)[::-1]:
			R[_] = L[_+1]
			L[_] = "".join([str(int(a)^int(b)) for a,b in self.zip_(R[_+1],L[_+1])])
				
		return self.b2s(L[0]+R[0])

	def b2s(self,bins):
		return "".join([chr(int(ele,2)) for ele in re.findall(r"\d{8}",bins)])

	def b2h(self,strs):
		return hex(int(strs,2))


class test(unittest.TestCase):
	"""docstring for test"""
	def test_base(self):
		key = "123433"
		plaintext = "abcdf"

		f = Feistel(key,3)
		Ln,Rn = f.encrypt(plaintext)
		plaintext_ = f.decrypt(Ln,Rn)

		self.assertEqual(plaintext,plaintext_)

	def test_new_F(self):
		key = "123433"
		plaintext = "abcdf"

		def _f(a,keys):
			return bin(a *1234 * keys)[2:]

		f = Feistel(key,3,f=_f)
		Ln,Rn = f.encrypt(plaintext)
		plaintext_ = f.decrypt(Ln,Rn)

		self.assertEqual(plaintext,plaintext_)

	def test_different_types_string(self):
		key = b'\xe4Q`\xdb!F\x0c\xfb\xbdZ\xb8?&%A\xf2'
		plaintext = "abcdf"

		f = Feistel(key,3)
		Ln,Rn = f.encrypt(plaintext)
		plaintext_ = f.decrypt(Ln,Rn)

		self.assertEqual(plaintext,plaintext_)

	def test_strange_inpt1(self):
		key = "12#A33"
		plaintext = "@!#CASF:"

		f = Feistel(key,3)
		Ln,Rn = f.encrypt(plaintext)
		plaintext_ = f.decrypt(Ln,Rn)

		self.assertEqual(plaintext,plaintext_)

	def test_strange_inpt2(self):
		key = b'\xe4Q`\xdb!F\x0c\xfb\xbdZ\xb8?&%A\xf2'
		plaintext = b'\xe4Q`\xdb!F\x0c\xfb\xbdZ\xb8?&%A\xf2'

		f = Feistel(key,3)
		Ln,Rn = f.encrypt(plaintext)
		plaintext_ = f.decrypt(Ln,Rn)
		plaintext_ = unhexlify(plaintext_)
		self.assertEqual(plaintext,plaintext_)

if __name__ == '__main__':

	unittest.main()