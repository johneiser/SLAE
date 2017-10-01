#!/bin/bash

if [ -z "$1" ]
then
	echo "Usage: $0 <file>"
	exit 0
fi

if [ ! -f "$1.nasm" ]
then
	echo "[-] Cannot find file $1.nasm"
	exit 0
fi

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

if [ ! $? -eq 0 ]
then
	echo "[-] Assembly failed, exiting"
	exit 0
fi

echo '[+] Linking ...'
ld -o $1 $1.o

if [ ! $? -eq 0 ]
then
	echo "[-] Linking failed, exiting"
	exit 0
fi

echo '[+] Done!'



