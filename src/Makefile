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
boost= -O2
# incmac =  -lboost_thread -lpthread 
incmac =  -lpthread 
inc = -lpthread
# inc =-I../lib/boost-linux/ -L../lib/boost-linux/stage/lib -lboost_thread -pthread
mac = -D MAC_OS  
# mac = -D MAC_OS -I../lib/boost-mac/ -L../lib/boost-mac/stage/lib -L/usr/lib/system 
release_en= -m64 -std=c++17  cc20_multi.cpp -D DEEP_DEBUG -lm  -Wall -fconcepts -D PRINTING -O1 -D LINUX  -o c20.o
release_de= -m64 -std=c++17  cc20_multi.cpp -D DEEP_DEBUG -lm  -Wall -fconcepts -D PRINTING -O1 -D LINUX -D DE -o c20de.o
release_en1= -m64 -std=c++11  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D LINUX -o c20
release_de1= -m64 -std=c++11  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D LINUX -D DE -o c20de
en_debug= -m64 -std=c++11  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D LINUX -o d20
de_debug= -m64 -std=c++11  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D LINUX -D DE -o d20de
release_en12= -m64 -std=c++17  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D ROUNDCOUNTTWLV -D LINUX -o c20.c
release_de12= -m64 -std=c++17  cc20_multi.cpp -lm  -Wall -D DEEP_DEBUG -D PRINTING -D ROUNDCOUNTTWLV -D LINUX -D DE -o c20de.c
release_en:
	g++ $(hash) $(boost) $(release_en) $(inc)
release_de:
	g++ $(hash) $(boost) $(release_de) $(inc)
en:
	g++ $(hash) $(boost) $(release_en1) $(inc)
de:
	g++ $(hash) $(boost) $(release_de1) $(inc)
en_debug:
	g++ $(hash) -D VERBOSE $(boost) $(en_debug) $(inc)
de_debug:
	g++ $(hash) -D VERBOSE $(boost) $(de_debug) $(inc)
enmac:
	clang++ $(mac) $(hash) $(boost) $(release_en1) $(incmac)
demac:
	clang++ $(mac) $(hash) $(boost) $(release_de1) $(incmac)
12en:
	g++ $(hash) $(boost) $(release_en12) $(inc)
12de:
	g++ $(hash) $(boost) $(release_de12) $(inc)

