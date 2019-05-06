from binascii import unhexlify, hexlify

class _32ary(object):
	
	def __init__(self, _dec=None, _hex=None, _bin=None):
		self._dec = _dec
		self._hex = _hex
		if _bin:
			self._dec =	int(_bin, 2)
		if _hex:
			try:
				_hex = hexlify(_hex)
			except Exception as e:
				pass
			self._dec = int(_hex, 16)

	def to_32ary(self):
		arr = []
		mod = None
		while self._dec != 0:
			mod = self._dec % 32
			arr += [mod]
			self._dec = int(self._dec/32)

		string = "0123456789abcdefghijklmnopqrstuv"

		return "".join(map(lambda n: string[n] , arr[::-1])).encode()
	

if __name__ == '__main__':
	ary = _32ary(27830000052)
	print(ary.to_32ary())
	ary = _32ary(_hex="67ACC19B4")
	print(ary.to_32ary())
	ary = _32ary(_bin="11001111010110011000001100110110100")
	print(ary.to_32ary())