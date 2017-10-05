#!/usr/bin/python

import sys

if (len(sys.argv) != 2):
	print "Usage: %s \"<shellcode>\"" % sys.argv[0]

str = sys.argv[1]
len = len(str)/4
print "Shellcode Length: %d" % len
