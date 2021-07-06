#!/bin/bash
cd src
sh build_t
printf "1234\n" | ./c20 short.sh
printf "1234\n" | ./c20de short.sh
cd ../

