#!/bin/bash
TXT="bout.temp"
PDF="test.pdf"
TEST="index.html"
printf "1234\n"|./c20 ${TEST} -h
# printf "msg\n 1\n 1\n"|./c20.c 

echo "----------------------------------------------------------------------------------------------"
printf "1234\n"|./c20de ${TEST} -h
# echo "----------------------------------------------------------------------------------------------"
# printf "12345\n"|./c20de ${TEST} -h

