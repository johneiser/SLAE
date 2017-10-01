#!/bin/sh

if [ -z "$1" ]
then
	echo "Usage: $0 <object>"
	exit 0
fi

if [ ! -f "$1" ]
then
	echo "[-] Cannot find file $1"
	exit 0
fi

objdump -d "$1"|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
