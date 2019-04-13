from binascii import unhexlify, hexlify
import unittest
import re
import warnings
from _warn import ParamWarning, ParamError
from Crypto import Random

class Lai_Massey(object):
	
	def __init__(self, key, rounds, f=None, h=None, h_=None):
		self.key = self.all2bin(key)
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

	def all2bin(self,value,types=None):

		if types == 16:
			result = "{0:#010b}".format(int(value, 16))[2:]
			while len(result)%8 !=0:
				# Something will lose leading zero, when we transform hex to binary.
				result = "0" + result
			return result

		try:
			return ''.join(format(ord(x), '#010b')[2:] for x in value) # 8bit is necessary.
		except Exception as e:
			pass

		try:
			return self.all2bin(hexlify(value).decode())
		except Exception as e:
			pass

	def F_(self,a,key):
		# F need to return a positive integer that can ensure L and R is positive.
		p = a*key
		return p if p>0 else -p


	def H(self,L,R):
		# If you did different process to L compare to R,
		#	 so you will drawn into a complicated math question.
		#	 because that time H_ is not H^(-1).
		# To 2019-04-07 20:58:26, i test + - * / ^ << >>. Found (+,-) and (<<,>>) and (^) can finish it simple.
		# Matrix maybe possible. because `offset`. 
		'''test'''
		#return L + 20, R + 20 # work -1
		#return L + self.key,R + self.key # work -1 extra
		#return L << 2, R << 2 # work -2
		return L ^ self.key,R ^ self.key # work -3
		#return L,R
		

	def H_(self,L,R):
		'''test'''
		#return L - 40, R - 40 # work -1
		#return L - 2*self.key,R - 2*self.key # work -1 extra
		#return L >> 4, R >> 4 # work -2
		return L ^ self.key,R ^ self.key # work -3
		#return L,R
		

	def encrypt(self,plaintext):
		lens = int(len(plaintext)/2)
		L = self.all2bin(plaintext[:lens])
		R = self.all2bin(plaintext[lens:])
		
		L_, R_, self.key = int(L,2), int(R,2), int(self.key, 2)
		
		L_, R_ = self.H(L_, R_)
		for _ in range(self.rounds):
			T = self.F(L_- R_, self.key)
			L_, R_ = self.H(L_ + T, R_ + T)
		
		# Same string size is necessary. otherwise we can't decrypt correctly.
		L_str = R_str = '{:02x}'
		if L_ > R_:
			L_hex = L_str.format(L_)
			R_str_ = '{:0%dx}'%len(L_hex)
			R_hex = R_str_.format(R_)
		else:
			R_hex = R_str.format(R_)
			L_str_ = '{:0%dx}'%len(R_hex)
			L_hex = L_str_.format(L_)
		
		return  L_hex + R_hex

	def decrypt(self,ciphertext):
		lens = int(len(ciphertext)/2)
		L_, R_ = int(ciphertext[:lens], 16), int(ciphertext[lens:], 16)
		
		L_, R_ = self.H(L_, R_)
		for _ in range(self.rounds):
			T = self.F(L_ - R_, self.key)
			L_, R_ = self.H_(L_ - T, R_ - T)
		
		bins = ["{0:#010b}".format(int(v)).replace("b","0") for v in [L_,R_]]
		for b in bins: 
			# 8bits per thing.
			length = len(b)%8
			if length == 0:
				continue
			elif length == 1:
				bins[bins.index(b)] = bins[bins.index(b)][1:]
			else:
				bins[bins.index(b)] = "0" + bins[bins.index(b)]

		return "".join(self.b2s(b) for b in bins)
	
	def b2s(self,bins):
		return "".join([chr(int(ele,2)) for ele in re.findall(r"\d{8}",bins)])




class test(unittest.TestCase):
	
	def test_base(self):
		key = "ADAW2FS4242f"
		plaintext = "abcdfedada231#"

		f = Lai_Massey(key,4)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)

	def test_new_F(self):
		key = "123433"
		plaintext = "abcdf"

		def _f(a,keys):
			p = a *1234 * keys
			return p if p > 0 else -p

		f = Lai_Massey(key,2,f=_f)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)

	def test_different_types_string(self):
		key = b'\xe4Q`\xdb!F\x0c\xfb\xbdZ\xb8?&%A\xf2'
		plaintext = "abcdf"

		f = Lai_Massey(key,2)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)

	def test_strange_inpt1(self):
		key = "12#A33"
		plaintext = "@!#CASF:"

		f = Lai_Massey(key,2)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)

		self.assertEqual(plaintext,plaintext_)

	def test_strange_inpt2(self):
		key = b'\xe4Q`\xdb!F\x0c\xfb\xbdZ\xb8?&%A\xf2'
		plaintext = b'\xe4Q`\xdb!F\x0c\xfb\xbdZ\xb8?&%A\xf2'

		f = Lai_Massey(key,2)
		ciphertext = f.encrypt(plaintext)
		plaintext_ = f.decrypt(ciphertext)
		plaintext_ = unhexlify(plaintext_)
		self.assertEqual(plaintext,plaintext_)

	def test_strange_inpt3(self):
		for _ in range(10):
			key = Random.new().read(1600)
			plaintext = Random.new().read(1600)

			key = hexlify(key).decode()
			plaintext = hexlify(plaintext).decode()

			f = Lai_Massey(key,2)
			ciphertext = f.encrypt(plaintext)
			plaintext_ = f.decrypt(ciphertext)
			self.assertEqual(plaintext,plaintext_)

if __name__ == '__main__':

	unittest.main()