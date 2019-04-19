from binascii import unhexlify, hexlify
import unittest
import re
import warnings
from operator import xor
import textwrap
from functools import reduce
import sys
import hashlib

from block_split import block

def padding(value):
	"""
	A block cipher works on units of a fixed size (known as a block size),
	but messages come in a variety of lengths.
	So some modes (namely ECB and CBC) require that the final block be padded before encryption.
	How to pad it? !but care must be taken that the original length of the plaintext can be recovered;!
		1. add \x00
		2. add a single one bit, followed by enough zero bits to fill out the block;
			if the message ends on a block boundary, a whole padding block will be added.
			ciphertext + 1 + 0*n
	"""
	raise NotImplementedError

class Mode(object):

	def __init__(self, key, encrypt, decrypt, **kw):
		self._iv = kw.get("IV")
		self.IV = self.toint(kw.get("IV"))
		self.counter = kw.get("counter")
		self.key = key

		# Be reuseable, through applying function instead of embedding all class into a cipher.
		self._encrypt = encrypt
		self._decrypt = decrypt

		self.plaintext = None
		self.ciphertext = None

	def toint(self,value):
		
		return int(self.tobin(value), 2)

	def tobin(self,value):
		try:
			b = ''.join(format(ord(x), '#010b')[2:] for x in value)
		except Exception as e:
			try:
				b = ''.join(format(x, '#010b')[2:] for x in value)
			except Exception as e:
				b = ''.join(format(value, '#010b')[2:])
		while len(b)%8:
			b = "0" + b
		return b

	@property
	def digest(self):
		return bytes(
				self.tobin(self.ciphertext))

	@property
	def hexdigest(self):
		return hexlify(self.digest)

	def to_bytes(self,array):
		bins = map(self.tobin, array)
		byte = lambda bins: bytes([int(ele,2) for ele in re.findall(r"\d{8}",bins)])
		return b"".join(map(byte, bins))

class ECB(Mode):
	"""
		ECB
		Electronic Codebook
	Encryption parallelizable:	Yes
	Decryption parallelizable:	Yes
	Random read access:	Yes
	"""

	def encrypt(self,p):
		output = []
		for p_ in p:
			output += [self._encrypt(p_)]
		
		return output

	def decrypt(self,c):
		output = []
		for c_ in c:
			output += [self._decrypt(c_)]
		return self.to_bytes(output)

class CBC(Mode):
	"""
		CBC
		Cipher Block Chaining
	Encryption parallelizable:	No
	Decryption parallelizable:	Yes
	Random read access:	Yes
	"""
	def encrypt(self,p):
		"""
		Ci = Ek(Pi xor Ci-1)
		C0 = IV
		"""
		output = []
		IV = self.IV
		for _,p_ in enumerate(p):
			out = self._encrypt(p_ ^ IV)
			output += [out]
			IV = out
		return output

	def decrypt(self,c):
		"""
		Pi = Dk(Ci) xor Ci-1
		C0 = IV
		"""
		output = []
		IV = self.IV
		for _,c_ in enumerate(c):
			out = self._decrypt(c_) ^ IV
			output += [out]
			IV =  c_
		return self.to_bytes(output)

class PCBC(Mode):
	"""
	# size of IV alawys bigger than px
		PCBC
		Propagating Cipher Block Chaining
	Encryption parallelizable:	No
	Decryption parallelizable:	No
	Random read access:	No
	"""
	def encrypt(self,p):

		IV = self.IV
		p = block(plaintext=p, vector=self._iv).blocks_int

		output = []
		for px in p:
			state = px ^ IV
			state = self._encrypt(state)
			IV = state ^ px
			#px = state
			output += [state]

		return self.to_bytes(output)

	def decrypt(self,c):
		#print(c,"cx")
		IV = self.IV
		c = block(plaintext=c, vector=self._iv).blocks_int
		output = []
		for cx in c:
			state = self._decrypt(cx)
			state = state ^ IV
			IV = cx ^ state
			output += [state]

		return self.to_bytes(output)

class CFB(Mode):
	"""
		CFB
		Cipher Feedback
	Encryption parallelizable:	No
	Decryption parallelizable:	Yes
	Random read access:	Yes
	"""
	def encrypt(self,p):
		# Ci = Ek(C_{i-1}) xor Pi
		p = block(plaintext=p, vector=self._iv).blocks_int
		IV = self.IV
		output = []
		for px in p:
			state = self._encrypt(IV) ^ px
			IV = state
			output += [state]

		return self.to_bytes(output)

	def decrypt(self,c):
		# Pi = Ek(C_{i-1}) xor Ci
		IV = self.IV
		c = block(plaintext=c, vector=self._iv).blocks_int
		output = []
		for cx in c:
			state = self._encrypt(IV) ^ cx
			IV = cx
			output += [state]

		return self.to_bytes(output)

class CFBm(Mode):
	# CFB modified version

	def head(self,s):
		return int(s/(10**self.x))

	def encrypt(self,p):
	
		p = block(plaintext=p, vector=self._iv).blocks_int

		self.x = 8
		S = self.IV
		n = len(str(self.IV))
		output = []
		for px in p:
			state = self.head(self._encrypt(S)) ^ px
			S = ((S << self.x) + state) % (2**n)
			output += [state]

		return self.to_bytes(output)

	def decrypt(self,c):
		c = block(plaintext=c, vector=self._iv).blocks_int
		self.x = 8
		S = self.IV
		n = len(str(self.IV))
		output = []
		for cx in c:
			state = self.head(self._encrypt(S)) ^ cx
			S = ((S << self.x) + state) % (2**n)
			output += [state]

		return self.to_bytes(output)

		

class OFB(Mode):
	"""
	Oj = Ek(Ij)
	Ij = O_{j-1}
	I0 = IV
	Cj = Pj xor Oj
	Pj = Cj xor Oj

		OFB
		Output Feedback
	Encryption parallelizable:	No
	Decryption parallelizable:	No
	Random read access:	No
	"""
	def encrypt(self,p):

		p = block(plaintext=p, vector=self._iv).blocks_int
		IV = self.IV
		output = []
		for px in p:
			o = self._encrypt(IV)
			output += [px ^ o]
			IV = o
		
		return self.to_bytes(output)

	def decrypt(self,c):

		IV = self.IV
		c = block(plaintext=c, vector=self._iv).blocks_int
		output = []
		for cx in c:
			o = self._encrypt(IV)
			output += [cx ^ o]
			IV = o

		return self.to_bytes(output)

class CTRm(Mode):
	"""
	A modified version of CTR. Ordinary CTR have to input counter function, but CTRm(CTR modified) can change IV to a Nonce.
		CTR
		Counter
	Encryption parallelizable:	Yes
	Decryption parallelizable:	Yes
	Random read access:	Yes
	"""
	def _counter(self,count):
		# create fixed size nonce and counter. 16bytes = 64bits
		return self.toint(hashlib.sha384(self._iv + bytes(count)).digest()[:len(self._iv)])

	def encrypt(self,p):

		p = block(plaintext=p, vector=self._iv).blocks_int
		output = []
		for _,px in enumerate(p):
			output += [self._encrypt(self._counter(_)) ^ px]

		return self.to_bytes(output)

	def decrypt(self,c):

		c = block(plaintext=c, vector=self._iv).blocks_int
		output = []
		for _,cx in enumerate(c):
			output += [self._encrypt(self._counter(_)) ^ cx]

		return self.to_bytes(output)

class XTS(Mode):
	# https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS
	"""
	P is the plaintext,
	i is the number of the sector,
	alpha  is the primitive element of GF(2^{128}) defined by polynomial x; i.e., the number 2,
	j is the number of the block within the sector.
	"""
	def encrypt(self,p):
		raise NotImplementedError

	def decrypt(self,c):
		raise NotImplementedError
	

class test(unittest.TestCase):
	"""
	CBC and ECB -> size of plaintext % size of IV == 0, 
	otherwise they may be not producing a final ciphertext block that is the same size as the final partial plaintext block.
	
	If the plaintext to be encrypted is not an exact multiple,
	 you need to pad before encrypting by adding a padding string. When decrypting,
	 the receiving party needs to know how to remove the padding in an unambiguous manner.

	为对称密钥加密设计的块密码工作模式要求输入明文长度必须是块长度的整数倍，因此信息必须填充至满足要求
	正常情况下会将明文进行N块拆分再加密, 8bytes/block, 16bytes/block. 
	因此只有CBC,ECB这样不加密后xor的mode会导致输出长度不一致

	To all modes SIZE OF IV MUST LARGER THAN BLOCKSIZE!
	"""
	def test_ECB(self):
		mode = ECB(key=b"awdad",encrypt=lambda x: x + 3,decrypt=lambda x: x - 3, IV=b"abcd")
		cipher = mode.encrypt(b"efghf")
		plain  = mode.decrypt(cipher)
		self.assertEqual(b"efghf", plain)
	
	def test_CBC(self):
		mode = CBC(key=b"awdad",encrypt=lambda x: x + 3,decrypt=lambda x: x - 3, IV=b"abcd")
		cipher = mode.encrypt(b"efghf")
		plain  = mode.decrypt(cipher)
		self.assertEqual(b"efghf", plain)

	def test_PCBC(self):
		mode = PCBC(key=b"awdad",encrypt=lambda x: x + 9,decrypt=lambda x: x - 9, IV=b"abcdefgh")
		cipher = mode.encrypt(b"efghfg")
		plain = mode.decrypt(cipher)
		self.assertEqual(b"efghfg",plain)

	def test_CFB(self):
		mode = CFB(key=b"awdad",encrypt=lambda x: x + 9, decrypt=lambda x: x - 9, IV=b"abcd")
		cipher = mode.encrypt(b"efgh")
		plain = mode.decrypt(cipher)
		self.assertEqual(b"efgh",plain)

	def test_CFBm(self):
		mode = CFBm(key=b"awdad",encrypt=lambda x: x + 9, decrypt=lambda x: x - 9, IV=b"abcd")
		cipher = mode.encrypt(b"efghfg")
		plain = mode.decrypt(cipher)
		self.assertEqual(b"efghfg",plain)

	def test_OFB(self):
		mode = OFB(key=b"awdad",encrypt=lambda x: x + 9, decrypt=lambda x: x - 9, IV=b"abcd")
		cipher = mode.encrypt(b"efgh")
		plain = mode.decrypt(cipher)
		self.assertEqual(b"efgh",plain)

	def test_CTRm(self):
		mode = CTRm(key=b"awdad",encrypt=lambda x: x + 9, decrypt=lambda x: x - 9, IV=b"abcd")
		cipher = mode.encrypt(b"efghefgh")
		plain = mode.decrypt(cipher)
		self.assertEqual(b"efghefgh",plain)
	
if __name__ == '__main__':

	unittest.main()	