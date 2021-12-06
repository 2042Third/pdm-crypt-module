#include <iostream>
#include <string>
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <cstdlib>
#include <unistd.h>
using namespace std;

int main (int argc , char** argv){
  int tick = 50;
  int cur_tick=0;
  string line, spaces;
  double num =0;
  line="";
  spaces="";
  while (cur_tick <= tick){
    printf("[%s%s]%.1f%\f\r",line.data(), spaces.data(), ((num/50)*100));
    line="";
    spaces="";
    num+=1;
    cur_tick+=1;
    for(unsigned i =0 ; i<tick;i++){
      if (i<=cur_tick)
        line+="-";
      else
        spaces+=" ";
    }
    usleep(100000); 
  }
  return 1;
}
