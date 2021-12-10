
#ifndef EMPP_CPP
#define EMPP_CPP
#include <stdio.h>
#include <string>
#include <vector>
#include "cc20_multi.h"
#include "sha3.h"
#include <iostream>
#include <sstream>
#include <stdlib.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/bind.h>
#endif
using namespace std;





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
  // cout <<"Size: "<<input.size()<< " Encryption start: "<<input << endl;

  vector<char> buf;    //= new vector<uint8_t>();
  vector<char> outstr; // = new vector<uint8_t>();
  buf.reserve(input.size() + 1);
  set_up(buf, input);
  outstr.reserve(input.size() + 30);
  cmd_enc((uint8_t *)((&buf)->data()), input.size(), (uint8_t *)((&outstr)->data()), key);
  cout << "Encryption complete: " << endl;
  char outarr[(input.size() + 30) * 3]; // do the web array
  std::ostringstream outt;
  size_t ac = 0;
  for (int i = 0; i < input.size() + 28; i++)
  {
    // printf("%03d ", (uint8_t)outstr[i]);
    sprintf(outarr + ac, "%03d", (uint8_t)outstr[i]);
    ac += 3;
  }
  sprintf(outarr + ac, "%03d000", 0);
  string str = outarr;
  return str;
}

string cvrt(string a, size_t b){
  string o="";
  uint8_t oi;
  for (int i=0; i<b; i++){
    char t[3];
    t[0] = a[i*3 + 0];
    t[1] = a[i * 3 + 1];
    t[2] = a[i * 3 + 2];
    // t[3] = '\0';
    
    oi = atoi(t);
    o.append(1,oi);
  }

  cout<<endl;
  return o;
}

string loader_out(std::string key, std::string inputi)
{
  vector<char> buf;    //= new vector<uint8_t>();
  vector<char> outstr; // = new vector<uint8_t>();
  size_t inpsize = (inputi.size() - 6) / 3;
  // cout <<"Size: "<<inpsize << endl;
  // cvrt();
  string input = cvrt(inputi, inpsize);
  buf.reserve(inpsize + 1);
  set_up(buf, input);
  outstr.reserve(inpsize - 10);
  cmd_dec((uint8_t *)((&buf)->data()), inpsize, (uint8_t *)((&outstr)->data()), key);
  cout << "Decryption complete: " << endl;
  std::ostringstream outt;
  stringstream ss;
  string str="";
  for (int i = 0; i < inpsize - 12-16; i++)
  {
    // printf(" %d", outstr[i]);
    str.append(1,(char)outstr[i]);
    // str=str+outstr[i];
  }
  return str;
}

string get_hash(string a){
  SHA3 vh;
  vh.add(a.data(),a.size());
  string b = vh.getHash();
  return b;
}

#ifdef WEB_TEST
int main(int argc, char **argv)
{
  string k="";
  string v="";
  cout << "Key: \n";
  getline(cin, k);
  cout << "Value: \n";
  getline(cin, v);
  std::cout<<"Hash: " << get_hash(v)<<std::endl;
  std::string a="";
  a = loader_check(k, v);

  std::cout<<"\nWe got: "<<a<<std::endl;
  std::string b ="";
  b= loader_out(k, a);
  std::cout << "\nDec we got: " << b << std::endl;
}
#endif //END_TEST

#ifdef __EMSCRIPTEN__
EMSCRIPTEN_BINDINGS(raw_pointers) {
  emscripten::register_vector<uint8_t>("CharList");
  emscripten::function("loader_check", &loader_check);
  emscripten::function("loader_out", &loader_out);
  // emscripten::function("cmd_enc", &cmd_enc, emscripten::allow_raw_pointers());
  // emscripten::function("cmd_dec", &cmd_dec, emscripten::allow_raw_pointers());
  emscripten::function("get_hash",&get_hash);
}
#endif


#endif //EMPP_CPP