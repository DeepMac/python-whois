# Declare exceptions for this module.
# TODO: ACTUALLY declare exceptions, :/

class UnknownTld(Exception):
	pass


class FailedParsingWhoisOutput(Exception):
	pass


class UnknownDateFormat(Exception):
	pass


class WhoisCommandFailed(Exception):
	pass
