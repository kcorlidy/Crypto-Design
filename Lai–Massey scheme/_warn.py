import warnings

class ParamWarning(Warning):
	__name__ = "ParamWarning"

class ParamError(Exception):

	def __init__(self, message, expression=None):
		self.expression = expression
		self.message = message
