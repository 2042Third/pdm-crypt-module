#!/bin/bash

printf "testing.mp4\n1234\n1\n"|./c20de 
printf "end for 20 round 1gb\n\n"
printf "testing.mp4\n1234\n1\n"|./c20de.c
printf "end for reduced round 1gb\n\n"

BSIZE=$(cat cc20_multi.cpp | grep tworounds | head -n 1)
echo ${BSIZE}