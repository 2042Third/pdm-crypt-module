lib = -I../clean_src/
args = -m64 -std=c++17  -D WINDOWS -D LINUX 
libr = -I../lib/
srcs = ../clean_src/cc20_file.cpp ../lib/cpp-mmf/memory_mapped_file.cpp
main:
	g++ poly_test.cpp $(libr) $(lib) $(args) ../src/cc20_multi.cpp -O2 -o test 
file:
	g++ mmf_test.cpp $(srcs) $(libr) $(lib) $(args) -O2 -g -o f_test 
carage_r:
	g++ r_test.cpp -O2 -g -o r_test

