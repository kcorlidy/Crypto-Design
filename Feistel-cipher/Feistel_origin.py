from binascii import a2b_hex, b2a_hex
import unittest
import re

class Feistel(object):
	"""docstring for Fi"""
	def __init__(self, key, rounds, f=None):
		self.s2b = lambda st: ''.join(format(ord(x), 'b') for x in st)
		self.key = self.s2b(key)
		self.rounds = rounds
		self.F = f if f else Feistel.F


	def F(a,key):
		return bin(int(a, 2) * int(key, 2))[2:]

	def zip_(self,first,second):
		return zip(list(first),list(self.F(second,self.key)))

	def encrypt(self,plaintext):
		lens = int(len(plaintext)/2)
		L = [self.s2b(plaintext[:lens])]
		R = [self.s2b(plaintext[lens:])]

		for _ in range(self.rounds):	
			L += [R[_]]
			R += ["".join([str(int(a)^int(b)) for a,b in self.zip_(L[_],R[_])])]
				
		return L[-1],R[-1]

	def decrypt(self,Ln,Rn):
		L = [None]*self.rounds + [Ln]
		R = [None]*self.rounds + [Rn]
		for _ in range(self.rounds)[::-1]:
			R[_] = L[_+1]
			L[_] = "".join([str(int(a)^int(b)) for a,b in self.zip_(R[_+1],L[_+1])])
				
		return self.b2s(L[0]+R[0])

	def b2s(self,bins):
		return "".join([chr(int(ele,2)) for ele in re.findall(r"\w{7}",bins)])

	def b2h(self,strs):
		return hex(int(strs,2))

class test(unittest.TestCase):
	"""docstring for test"""
	def test_base(self):
		key = "1234"
		plaintext = "abcd"

		f = Feistel(key,3)
		Ln,Rn = f.encrypt(plaintext)
		plaintext_ = f.decrypt(Ln,Rn)

		self.assertEqual(plaintext,plaintext_)

if __name__ == '__main__':

	unittest.main()