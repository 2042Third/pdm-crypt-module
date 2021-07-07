@echo off

gcc -g  -O2 -m64 -std=c++17  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D WINDOWS -o c20 -pthread
echo "build en completed"
gcc -g  -O2 -m64 -std=c++17  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D WINDOWS -D DE -o c20de -pthread
echo "build de completed"


