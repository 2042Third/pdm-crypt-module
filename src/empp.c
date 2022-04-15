#include "empp.cpp"
#define c_main_compilation (!__cplusplus & WEB_TEST)

char* pp_hash_convert(char* user1, char* user2);

#ifdef c_main_compilation
int main(int argc, char** argv){
  fprintf(stderr, "%s\n","hello this is C's world!!!" );

}
#endif // c_main_compilation
