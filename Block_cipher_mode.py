from binascii import unhexlify, hexlify
import unittest
import re
import warnings

class Mode(object):
	"""
								Summary of modes
	Mode						Formulas											Ciphertext
	Electronic Codebook (ECB)	Yi=F(PlainTexti,Key)								Yi
	Cipher Block Chaining (CBC)	Yi=PlainTexti XOR Ciphertexti-1						F(Y,key); Ciphertext0=IV
	Propagating CBC (PCBC)		Yi=PlainTexti XOR (Ciphertexti-1 XOR PlainTexti-1)	F(Y,key);Ciphertext0=IV
	Cipher Feedback (CFB)		Yi=Ciphertexti-1									Plaintext XOR F(Y,key);Ciphertext0=IV
	Output Feedback (OFB)		Yi=F(Key,Yi-1);Y0=IV								Plaintext XOR Yi
	Counter (CTR)				Yi=F(Key,IV + g(i) );IV=token();					Plaintext XOR Yi
	"""
	def __init__(self, key, encrypt, decrypt , _rounds=1, **kw):
		self.IV = kw.get("IV")
		self.counter = kw.get("counter")
		self.key = key

		# Be reuseable, through applying function instead of embedding all class into a cipher.
		self.encrypt = encrypt
		self.decrypt = decrypt

		self._rounds = _rounds
		self.plaintext = None
		self.ciphertext = None

class ECB(Mode):
	
	def encrypt(self):
		pass

	def decrypt(self):
		pass

class CBC(Mode):

	def encrypt(self):
		pass

	def decrypt(self):
		pass

class PCBC(Mode):

	def encrypt(self):
		pass

	def decrypt(self):
		pass

class CFB(Mode):

	def encrypt(self):
		pass

	def decrypt(self):
		pass

class OFB(Mode):

	def encrypt(self):
		pass

	def decrypt(self):
		pass

class CTR(Mode):

	def encrypt(self):
		pass

	def decrypt(self):
		pass

class XEX(Mode):
	# https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS
	def encrypt(self):
		pass

	def decrypt(self):
		pass

class test(unittest.TestCase):
	
	def test(self):
		
	
if __name__ == '__main__':

	unittest.main()	