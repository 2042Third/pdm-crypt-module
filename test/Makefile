# Yi Yang, 11/7/2021
lib = -I../clean_src/
args = -m64 -std=c++17  -D WINDOWS -D LINUX 
libr = -I../lib/
srcs = ../clean_src/cc20_file.cpp ../lib/cpp-mmf/memory_mapped_file.cpp -I../lib/poly1305-donna-master/
src_ = ../clean_src
fs = $(src_)/cc20_file.cpp $(src_)/cc20_multi.cpp ../lib/cpp-mmf/memory_mapped_file.cpp ../lib/sha3.cpp 
df = -D LINUX -D SINGLETHREADING -D WEB_RELEASE -D WEB_TEST
cmpdf = -O2  -g -Wall -std=c++17 -I../lib/poly1305-donna-master/ ../lib/poly1305-donna-master/poly1305-donna.c 

main:
	g++ poly_test.cpp $(srcs) $(libr) $(lib) $(args) ../clean_src/cc20_multi.cpp -O2 -o test 
file:
	g++ mmf_test.cpp $(srcs) $(libr) $(lib) $(args) -O2 -g -o f_test 
carage_r:
	g++ r_test.cpp -O2 -g -o r_test
web_linux:
	g++ $(src_)/empp.cpp $(fs) $(df) $(cmpdf) $(libr)  -o safe_test 