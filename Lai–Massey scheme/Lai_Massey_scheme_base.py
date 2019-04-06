from binascii import unhexlify, hexlify
import unittest
import re
import warnings
from _warn import ParamWarning, ParamError
from Crypto import Random

class Lai_Massey(object):
	
	def __init__(self, key, rounds, f=None, h=None):
		self.key = self.all2int(key)
		self.rounds = rounds
		self.F = f if f else Lai_Massey.F
		self.H = h if h else Lai_Massey.H
		self.checkit(key)

	
	def checkit(self,key):
		if self.F != Lai_Massey.F:
			warnings.warn("You are using self-define F function, which have to return a binary string", ParamWarning,stacklevel=2)
		if len(key)%2 != 0:
			raise ParamError("Invalid key length")

	def all2int(self,value):
		try:
			return int(''.join(format(ord(x), '#010b')[2:] for x in value), 2) # 8bit is necessary.
		except Exception as e:
			try:
				return self.all2int(hexlify(value).decode())
			except Exception as e:
				pass

		raise ParamError("Can't decode your input.")

	def F(a,key):
		return pow(a * key,2)

	def H(L,R,T=None):
		return L,R


	def encrypt(self,plaintext):
		lens = int(len(plaintext)/2)
		L = self.all2int(plaintext[:lens])
		R = self.all2int(plaintext[lens:])

		# R0' = R_0, L0' = L0
		L_, R_ = self.H(L,R)
		for _ in range(self.rounds):
			T = self.F(L_ - R_, self.key)
			L_, R_ = self.H(L_ + T, R_ + T)

		print(L_,R_)
		return hex(L_)[2:],hex(R_)[2:]

	def decrypt(self,Ln,Rn):
		L, R = int(Ln, 16), int(Rn, 16)
		L_, R_ = self.H(L,R)
		print(L_,R_)
		for _ in range(self.rounds):
			T = self.F(L_ - R_, self.key)
			L_, R_ = self.H(L_ - T, R_ - T)

		return self.i2s((L_,R_))
	
	def i2s(self,ints):
		return "".join([chr(ele) for ele in ints])

	def b2s(self,bins):
		return "".join([chr(int(ele,2)) for ele in re.findall(r"\d{8}",bins)])

	def b2h(self,strs):
		return hex(int(strs,2))

if __name__ == '__main__':
	key = "123433"
	plaintext = "gc"
	f = Lai_Massey(key,2)
	Ln,Rn = f.encrypt(plaintext)
	print(Ln,Rn)

	print(f.decrypt(Ln,Rn))