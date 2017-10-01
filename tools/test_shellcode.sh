#!/bin/sh

if [ -z "$1" ]
then
	echo "Usage: $0 \"<shellcode>\""
	exit 0
fi

echo "#include <stdio.h>
#include <string.h>
unsigned char code[] = \"$1\";
int main(void) {
	int (*ret)() = (int(*)())code;
	ret();
}" > /tmp/test_shellcode.c

gcc -fno-stack-protector -z execstack -o /tmp/test_shellcode /tmp/test_shellcode.c

if [ $? -eq 0 ]
then
	/tmp/test_shellcode
else
	echo "[!] Compilation failed."
fi

if [ -f "/tmp/test_shellcode" ]
then
	rm /tmp/test_shellcode
fi

if [ -f "/tmp/test_shellcode.c" ]
then
	rm /tmp/test_shellcode.c
fi

