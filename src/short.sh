#!/bin/bash
TXT="bout.temp"
PDF='test.pdf'
pass="$(printf 1234\n)"
enc="$(./c20 test.pdf )"
dec="$(./c20de test.pdf )"
TEST="index.html"

echo "${pass} | ${enc}"
echo "${pass} | ${dec}"

