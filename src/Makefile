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
incmac = -lboost_thread-mt -lpthread 
inc = -lboost_thread -lpthread 
mac = -D MAC_OS -L /usr/local/Cellar/boost/1.76.0/lib -I /usr/local/Cellar/boost/1.76.0
release_en= -m64 -std=c++17  cc20_multi.cpp -D DEEP_DEBUG -lm  -Wall -fconcepts -D PRINTING -O1 -D LINUX  -o c20.o
release_de= -m64 -std=c++17  cc20_multi.cpp -D DEEP_DEBUG -lm  -Wall -fconcepts -D PRINTING -O1 -D LINUX -D DE -o c20de.o
release_en1= -m64 -std=c++17  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D LINUX -o c20
release_de1= -m64 -std=c++17  cc20_multi.cpp  -lm  -Wall -D DEEP_DEBUG -D PRINTING -D LINUX -D DE -o c20de
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
enmac:
	g++ $(mac) $(hash) $(boost) $(release_en1) $(incmac)
demac:
	g++ $(mac) $(hash) $(boost) $(release_de1) $(incmac)
12en:
	g++ $(hash) $(boost) $(release_en12) $(inc)
12de:
	g++ $(hash) $(boost) $(release_de12) $(inc)

