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
inc = -lboost_thread -lpthread 
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
12en:
	g++ $(hash) $(boost) $(release_en12) $(inc)
12de:
	g++ $(hash) $(boost) $(release_de12) $(inc)
cc20_multi2: 
	g++ $(ver) $(file3) $(dflg) $(sys2) -D ENG -o cc20.o
cc20_multi2_debug: 
	g++ $(ver) $(file3) $(dpflg) $(dflg) $(sys2) -D ENG -o c20.o
cc20_multi2_debug_dec: 
	g++ $(ver) $(file3) $(dpflg) $(dflg) $(sys2) -D ENG -D DE -o c20de.o
cc20_multi1: 
	g++ $(ver) $(file3) $(sys1) -D ENG -o cc20.o
cc20_multi3: 
	g++ $(ver) $(file3) $(sys3) -D ENG -o cc20.o
cc20_dev_lin: 
	g++ $(ver) $(file2) $(sys1) -D ENG -o cc20.o
clean:
	rm *.pdm
	g++ $(ver) $(file1) -o pdm.o
debug:
	g++ $(ver) $(dflg) $(file1) -o3 -o a.out
fast:
	g++ $(ver) $(file3) $(sys2) -o3 -o a.out
deepdebug1:
	g++ $(ver) $(dflg) $(dpflg) $(file1) -o a.out
deepdebug2:
	g++ $(ver) $(dflg) $(dpflg) $(file2) -o a.out
