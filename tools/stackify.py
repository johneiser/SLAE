#!/usr/bin/python

import sys

if (len(sys.argv) != 2):
	print "Usage: %s <string>" % sys.argv[0]

str = sys.argv[1]
str_rev = str[::-1]
hex = str_rev.encode("hex")

for i in range(0, len(str), 8):
	print "push 0x%s" % (hex[i:i+8])
