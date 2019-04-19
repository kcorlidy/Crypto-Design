from binascii import unhexlify, hexlify
import unittest
import re
import warnings
from _warn import ParamWarning, ParamError
from Crypto import Random

class Feistel(object):
	
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

	def all2bin(self,value,types=None):
		if types == 16:
			result = "{0:#010b}".format(int(value, 16))[2:]
			while len(result)%8 !=0:
				# something will lose leading zero.
				result = "0" + result
			return result

		try:
			return ''.join(format(ord(x), '#010b')[2:] for x in value) # 8bit is necessary.
		except Exception as e:
			return ''.join(format(x, '#010b')[2:] for x in value)

		raise ParamError("Can't decode your input.")

	def b2i(self,a,key):
		# I think i should make key can only be integer or binary.
		# binary to integer
		return int(a, 2), int(key, 2)

	def F(a,key):
		# a,key are integer.
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
		'''
		Try to use a big integer instead of bytes string. Integer may make everything simple.
		But it is not specification or not accuracy. 
		My explanation is that sometime you wanna encrypt 8bits string by using 64bits key. 
		So you need to divide 64bits into 8 parts. Then start the loop.
		'''
		lens = int(len(plaintext)/2)
		L = [self.all2bin(plaintext[:lens])]
		R = [self.all2bin(plaintext[lens:])]

		for _ in range(self.rounds):	
			L += [R[_]]
			R += ["".join([str(int(a)^int(b)) for a,b in self.zip_(L[_],R[_]) ])] # xor a whole string

		# Same string size is necessary. otherwise we can't decrypt correctly.
		L_str = R_str = '{:02x}'
		if L[-1] > R[-1]:
			L_hex = L_str.format(int(L[-1], 2))
			R_str_ = '{:0%dx}'%len(L_hex)
			R_hex = R_str_.format(int(R[-1], 2))
		else:
			R_hex = R_str.format(int(R[-1], 2))
			L_str_ = '{:0%dx}'%len(R_hex)
			L_hex = L_str_.format(int(L[-1], 2))
		
		return  L_hex + R_hex

	def decrypt(self,ciphertext):
		lens = int(len(ciphertext)/2)
		L = [None]*self.rounds + [self.all2bin(ciphertext[:lens], types=16)]
		R = [None]*self.rounds + [self.all2bin(ciphertext[lens:], types=16)]
		
		for _ in range(self.rounds)[::-1]:
			R[_] = L[_+1]
			L[_] = "".join([str( int(a)^int(b) ) for a,b in self.zip_(R[_+1],L[_+1])])
		
		return self.b2s(L[0]+R[0])

	def b2s(self,bins):
		return bytes([ int(ele,2) for ele in re.findall(r"\d{8}",bins)])

	def b2h(self,strs):
		return hex(int(strs,2))


class test(unittest.TestCase):
	
	def test_base(self):
		key = b"123433"
		plaintext = b"abcdf"

		f = Feistel(key,3)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)
	
	def test_new_F(self):
		key = b"123433"
		plaintext = b"abcdf"

		def _f(a,keys):
			return bin(a *1234 * keys)[2:]

		f = Feistel(key,3,f=_f)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)

	def test_different_types_string(self):
		key = b'\xe4Q`\xdb!F\x0c\xfb\xbdZ\xb8?&%A\xf2'
		plaintext = b"abcdf"

		f = Feistel(key,3)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)

	def test_strange_inpt1(self):
		key = b"12#A33"
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