#!/bin/bash
TXT="84.txt"
PDF="test.pdf"
TEST=${TXT}
printf "${TEST}\n1234\n1\n"|./c20 
# printf "msg\n 1\n 1\n"|./c20.c 

printf "${TEST}\n1234\n1\n"|./c20de