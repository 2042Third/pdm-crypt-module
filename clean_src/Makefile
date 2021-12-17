ver = -m64 -std=c++17 
dflg =  -g -Wall -fconcepts -D PRINTING
dpflg = -D DEEP_DEBUG -lm -D HARD_CODE_DEBUG
file1 = c20_dev.cpp
file2 = cc20_dev.cpp
file3 = cc20_multi.cpp
sys1 = -D WINDOWS
sys2 = -D LINUX -pthread
sys3 = -D MAC
hash =  -g 
boost= -O3 -I../lib/ -I../include/ -D HAS_MAIN
# incmac =  -lboost_thread -lpthread 
incmac =  -lpthread 
inc = -lpthread
# inc =-I../lib/boost-linux/ -L../lib/boost-linux/stage/lib -lboost_thread -pthread
mac = -D MAC_OS  
src_ = ../clean_src
libr = -I../lib/poly1305-donna-master/ 
win32 = -D WINDOWS 
srcs = ../clean_src/cc20_file.cpp ../lib/sha3.cpp ../lib/cpp-mmf/memory_mapped_file.cpp ../lib/poly1305-donna-master/poly1305-donna.c 
# srcs = ../clean_src/cc20_file.cpp ../lib/sha3.cpp ../lib/cpp-mmf/memory_mapped_file.cpp ../lib/poly1305-donna-master/poly1305-donna.c 
release_en= -m64 -std=c++17  cc20_multi.cpp -D DEEP_DEBUG -lm  -Wall -fconcepts -D PRINTING -O1 -D LINUX  -o c20.o
release_de= -m64 -std=c++17  cc20_multi.cpp -D DEEP_DEBUG -lm  -Wall -fconcepts -D PRINTING -O1 -D LINUX -D DE -o c20de.o
release_en1= -m64 -std=c++17  cc20_multi.cpp  -D LINUX -o c20
debug_web= -m64 -std=c++17  cc20_multi.cpp  -D LINUX   -D WEB_RELEASE -D WEB_TEST -O3 -I../lib/ -I../include/
release_de1= -m64 -std=c++17  cc20_multi.cpp   -D LINUX -o c20
en_debug= -m64 -std=c++11  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D LINUX -o d20
de_debug= -m64 -std=c++11  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D LINUX -D DE -o d20de
release_en12= -m64 -std=c++17  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D ROUNDCOUNTTWLV -D LINUX -o c20.c
release_de12= -m64 -std=c++17  cc20_multi.cpp -lm  -Wall -D DEEP_DEBUG -D PRINTING -D ROUNDCOUNTTWLV -D LINUX -D DE -o c20de.c
windows:
	g++ $(boost) $(release_en1) $(srcs) $(inc) $(win32)
windows_single:
	g++ $(boost) $(release_en1) $(srcs) $(inc) $(win32) -D SINGLETHREADING
windows_debug:
	g++ $(boost) $(release_en1) $(srcs) $(inc) $(win32) 
release_en:
	g++ $(hash) $(boost) $(release_en) $(inc)
release_de:
	g++ $(hash) $(boost) $(release_de) $(inc)
en:
	clang++ $(boost) $(srcs) $(release_en1) $(inc)
en_single:
	clang++ $(boost) $(srcs) $(release_en1) $(inc) -D SINGLETHREADING
de:
	clang++ $(boost) $(srcs) $(release_de1) $(inc) -g
web_linux:
	clang++  -I../include/ $(src_)/empp.cpp $(srcs) $(debug_web) $(inc) -g -D SINGLETHREADING -o ../test/web_debug
