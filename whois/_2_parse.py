# Purpose: Parse the output produced by whois query

# Import needed libraries
import re
from .exceptions import FailedParsingWhoisOutput
from . import tld_regexpr
from . import _1_query
from typing import Any, Dict, Optional

# Init variables
TLD_RE: Dict[str, Any] = {}

# Function to get the regex string for a specified TLD
def get_tld_re(tld: str) -> Any:
	if tld in TLD_RE:
		return TLD_RE[tld]
	elif tld == "in":
		return "in_"
	v = getattr(tld_regexpr, tld)
	extend = v.get('extend')

	if extend:
		e = get_tld_re(extend)
		tmp = e.copy()
		tmp.update(v)
	else:
		tmp = v

	if 'extend' in tmp:
		del tmp['extend']

	TLD_RE[tld] = dict((k, re.compile(v, re.IGNORECASE) if isinstance(v, str) else v) for k, v in tmp.items())
	return TLD_RE[tld]

# Loads the TLD regex data from the tld_regexpr.py module
[get_tld_re(tld) for tld in dir(tld_regexpr) if tld[0] != '_']

# Function to parse through whois data as a single string and extract metadata
# Will populate an object with any metadata that could be pulled
def do_parse(whois_str: str, tld: str) -> Optional[Dict[str, Any]]:
	r: Dict[str, Any] = {'tld': tld}

	if whois_str.count('\n') < 5:
		s = whois_str.strip().lower()
		if s == 'not found':
			return None
		if s.startswith('no such domain'):
			# could feed startswith a tuple of strings of expected responses
			return None
		if s.count('error'):
			return None
		raise FailedParsingWhoisOutput(whois_str)

	# check the status of DNSSEC
	r['DNSSEC'] = False
	whois_dnssec: Any = whois_str.split("DNSSEC:")
	if len(whois_dnssec) >= 2:
		whois_dnssec = whois_dnssec[1].split("\n")[0]
		if whois_dnssec.strip() == "signedDelegation" or whois_dnssec.strip() == "yes":
			r['DNSSEC'] = True

	# split whois_str to remove first IANA part showing info for TLD only
	whois_splitted = whois_str.split("source:	   IANA")
	if len(whois_splitted) == 2:
		whois_str = whois_splitted[1]

	sn = re.findall(r'Server Name:\s?(.+)', whois_str, re.IGNORECASE)
	if sn:
		whois_str = whois_str[whois_str.find('Domain Name:'):]

	for k, v in TLD_RE.get(tld, TLD_RE['com']).items():
		if v is None:
			r[k] = ['']
		else:
			r[k] = v.findall(whois_str) or ['']
#			print("DEBUG: Keyval = " + str(r[k]))

	return r