import sys
from binascii import unhexlify, hexlify
from operator import add, sub, rshift, lshift, mod, mul, xor
import unittest

def bytess(a):
	a = int(a)
	n = 1
	while 1:
		try:
			a = a.to_bytes(n, sys.byteorder)
			break
		except Exception as e:
			n += 1
	return a[::-1]

__doc__ = """All operators: 
		Mod, Mul,add, Sub, Rsh, lsh
	   Whatadvantage?
	    It operate on bytes instead of integer, though it used integer.
	   and operators will return byte(s), not integer.
	   also the return size of result will equal or longer than input, 
	    	because those operators build to handle special input in Crypto i.e. \x00.

	"""
	
	
def base(a, b, op):
	l = len(a)
	a = bytess( op(int(''.join(format(x, '#010b')[2:] for x in a), 2), b) )
	l = (l - len(a)) if (l - len(a)) >= 0 else 0
	return (b"\x00" * l) + a

	
def Mod(a, b):
	return base(a, b, mod)

	
def Mul(a, b):
	return base(a, b, mul)

	
def Add(a, b):
	return base(a, b,add)

	
def Sub(a, b):
	return base(a, b, sub)

	
def Rsh(a, b):
	return base(a, b, rshift)

	
def Lsh(a, b):
	return base(a, b, lshift)

	
def Xor(a,b):
	return b"".join( [ints.to_bytes(1, sys.byteorder) for ints in map(lambda x: xor(*x), zip(a,b))] )

def bytes2int(bytes_):
	return int(''.join(format(x, '#010b')[2:] for x in bytes_), 2)

class test(unittest.TestCase):
	"""docstring for test"""
	def test_op(self):
		a = b"\xff\xfe\xfd\xfc"
		int_a = int(hexlify(a), 16)
		mod_ = Mod(a, 3)
		mul_ = Mul(a, 3)
		lsh_ = Lsh(a, 3)
		rsh_ = Rsh(a, 3)
		add_ = Add(a, 1e4)
		sub_ = Sub(a, 1e4)
		print(hexlify(a), hexlify(mod_), mod_, "mod")
		print(hexlify(a), hexlify(mul_), mul_, "mul")
		print(hexlify(a), hexlify(lsh_), lsh_, "lsh")
		print(hexlify(a), hexlify(rsh_), rsh_, "rsh")
		print(hexlify(a), hexlify(add_),add_, "add")
		print(hexlify(a), hexlify(sub_), sub_, "sub")
		self.assertEqual(int_a % 3, int(hexlify(mod_), 16))
		self.assertEqual(int_a * 3, int(hexlify(mul_), 16))
		self.assertEqual(int_a << 3, int(hexlify(lsh_), 16))
		self.assertEqual(int_a >> 3, int(hexlify(rsh_), 16))
		self.assertEqual(int_a + 1e4, int(hexlify(add_), 16))
		self.assertEqual(int_a - 1e4, int(hexlify(sub_), 16))

if __name__ == '__main__':
	
	unittest.main()

