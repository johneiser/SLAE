#!/bin/bash

if [ -z "$1" ]
then
	echo "Usage: $0 \"<shellcode>\""
	exit 0
fi

echo -ne $1 | ndisasm -b 32 -p intel -
