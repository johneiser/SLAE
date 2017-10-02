#!/bin/bash

if [ -z "$1" ]
then
	echo "Usage: $0 \"<shellcode>\""
	exit 0
fi

echo -ne $1 > /tmp/disassemble_shellcode
ndisasm -b32 /tmp/disassemble_shellcode

if [ -f "/tmp/test_shellcode" ]
then
	rm /tmp/test_shellcode
fi
