#!/bin/bash

printf "test.mp4\n1234\n1\n"|./c20 
echo "end for 20 round 5gb\n\n"


printf "test.mp4\n1234\n1\n"|./c20.c
echo "end for reduced round 5gb\n\n"

BSIZE=$(cat cc20_multi.cpp | grep tworounds | head -n 1)
echo $BSIZE
