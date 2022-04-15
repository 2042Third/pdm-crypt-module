
#ifndef EMPP_CPP
#define EMPP_CPP
#include <stdio.h>
#include <string>
#include <vector>
#include "cc20_multi.h"
#include "ec.h"
#include "sha3.h"
#include <iostream>
#include <sstream>
#include <stdlib.h>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/bind.h>
#endif
using namespace std;

#define C20_ECC_SIZE 32

#define cplusplus_main_compilation (__cplusplus & WEB_TEST)

/**
 * @param a user1
 * @param b user2
 * 
 * */
string pp_hash(std::string user1, std::string user2){
  std::cout<<std::endl;//flush
  string c = user1.size()>user2.size()?user1:user2;
  string d = user1.size()>user2.size()?user2:user1;
  vector<char> buf(c.begin(),c.end()); 
  for (size_t i=0; i<d.size(); i++){
    buf[i] =(uint8_t)buf[i] +(uint8_t)d[i];
  }
  SHA3 vh;
  vh.add(buf.data(),buf.size());
  std::cout<<std::endl;//flush
  return vh.getHash();
}
/**
 * wrapper for calling from c
 * 
 * */
char* pp_hash_c(char* user1, char* user2){
  std::string u1 = std::string(user1);
  std::string u2 = std::string(user2);
  std::string out = pp_hash(u1, u2);
  return out.data();
}
extern "C" char* pp_hash_convert(char* user1, char* user2){
  std::string u1 = std::string(user1);
  std::string u2 = std::string(user2);
  std::string out = pp_hash(u1, u2);
  return out.data();
}

// EMSCRIPTEN_KEEPALIVE
void use_vector_string(const std::vector<uint8_t> &vec) {
    std::cout << "size() = " << vec.size() << ", capacity()=" << vec.capacity() << "\n";
    for (const auto &str : vec) {
        std::cout << "vec[]=|" << str << "|\n";
    }
}

void set_up(vector<char> &buf, string inp)
{
  for (char a : inp)
  {
    buf.push_back((uint8_t)a);
  }
}

string loader_check(std::string key, std::string input)
{
  vector<char> buf;    //= new vector<uint8_t>();
  vector<char> outstr; // = new vector<uint8_t>();
  buf.reserve(input.size() + 1);
  set_up(buf, input);
  outstr.reserve(input.size() + 30);
  cmd_enc((uint8_t *)((&buf)->data()), input.size(), (uint8_t *)((&outstr)->data()), key);
  std::ostringstream outt;
  stringstream ss;
  string str="";
  for (size_t i = 0; i <input.size()+28; i++)
  {
    str.append(1,outstr[i]);
  }
  cout<<str<<endl;
  return stoh( str);
}



string loader_out(std::string key, std::string inputi)
{
  vector<char> buf;    //= new vector<uint8_t>();
  vector<char> outstr; // = new vector<uint8_t>();
  char tchar;
  for (auto a : inputi)
    tchar = a;
  cout<<endl;
  string input = htos(inputi);
  size_t inpsize = (input.size()) ;
  buf.reserve(inpsize + 1);
  set_up(buf, input);
  cout << "Input lengths: "<<inpsize << endl;
  outstr.reserve(inpsize - 27);
  cmd_dec((uint8_t *)((&buf)->data()), inpsize, (uint8_t *)((&outstr)->data()), key);
  std::ostringstream outt;
  stringstream ss;
  string str="";
  for (size_t i = 0; i < inpsize -28; i++)
  {
    str.append(1,(char)outstr[i]);
  }
  return str;
}

/**
 * Return the secret key
 * 
 * */
string gen_sec(){
  uint8_t sec[C20_ECC_SIZE+1];
  sec[C20_ECC_SIZE]='\0';
  string tmpsec="";
  ECC20 ecc;
  ecc.gensec((uint8_t*)sec);
  for(size_t i=0;i<C20_ECC_SIZE;i++)
    tmpsec.append(1,(char)sec[i]);
  // #ifdef WEB_TEST
  // printf("gen_sec(): \"%s\"\n",sec);
  // #endif 
  return stoh(tmpsec);
}
/**
 * Return the public key
 * @param - a the secret key
 * */
string gen_pub(string a){
  uint8_t pub[33];
  pub[C20_ECC_SIZE]='\0';
  string tmpsec=htos(a);
  // #ifdef WEB_TEST
  // printf("gen_pub input: \"%s\"\n",tmpsec.data());
  // #endif 
  ECC20 ecc;
  ecc.setsec((uint8_t*)tmpsec.data());
  ecc.genpub(pub);
  string tmppub="";
  for(size_t i=0;i<C20_ECC_SIZE;i++)
    tmppub.append(1,(char)pub[i]);
  return stoh(tmppub);
}

/**
 * Return the shared key
 * @param - a the secret key
 * @param - c the other public key
 * */
string gen_shr(string a,  string c){
  uint8_t shr[33];
  shr[C20_ECC_SIZE]='\0';
  string tmpsec=htos(a);
  string tmp2pub=htos(c);
  ECC20 ecc;
  ecc.setsec((uint8_t*)tmpsec.data());
  ecc.genshr(shr,(uint8_t*)tmp2pub.data());
  string tmpshr="";
  for(int i=0;i<C20_ECC_SIZE;i++)
    tmpshr.append(1,(char)shr[i]);
  // #ifdef WEB_TEST
  // printf("gen_shr(a,c): \"%s\"\n",stoh(tmpshr).data());
  // #endif 
  return stoh(tmpshr);
}

string get_hash(string a){
  SHA3 vh;
  vh.add(a.data(),a.size());
  string b = vh.getHash();
  return b;
}

#ifdef cplusplus_main_compilation
int main(int argc, char **argv)
{
  size_t testsize=0;
  uint8_t test[32];
  string ttmp="3a57718b1da04cc0c52f626212e5c82a";
  for(auto i:ttmp){
    test[testsize]=i;
    testsize++;
  }
  string tmpshr="";
  for(int i=0;i<C20_ECC_SIZE;i++)
    tmpshr.append(1,(char)test[i]);
  // cout<<test<<endl;
  // cout<<stoh(tmpshr)<<endl;

  // Alice
  string seca = gen_sec();
  string puba = gen_pub(seca);

  // Bob
  string secb = gen_sec();
  string pubb = gen_pub(secb);

  //agreenent
  string shra = gen_shr(seca,pubb);
  string shrb = gen_shr(secb,puba);
  printf("Alice secret and public: \"%s\", \"%s\"\n",seca.data(),puba.data());
  printf("Bob   secret and public: \"%s\", \"%s\"\n",secb.data(),pubb.data());
  printf("Alice shared: \"%s\"\n",shra.data());
  printf("Bob   shared: \"%s\"\n",shrb.data());


  return 0;
}
#endif //END_TEST

#ifdef __EMSCRIPTEN__
EMSCRIPTEN_BINDINGS(raw_pointers) {
  emscripten::register_vector<uint8_t>("CharList");
  emscripten::function("loader_check", &loader_check);
  emscripten::function("loader_out", &loader_out);
  emscripten::function("get_hash",&get_hash);
  emscripten::function("pp_hash",&pp_hash);
  emscripten::function("gen_sec",&gen_sec);
  emscripten::function("gen_pub",&gen_pub);
  emscripten::function("gen_shr",&gen_shr);
}
#endif


#endif //EMPP_CPP