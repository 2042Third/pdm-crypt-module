
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
  for (size_t i = 0; i < outstr.size(); i++)
  {
    str.append(1,(char)outstr[i]);
  }
  return stoh( str, str.size());
}



string loader_out(std::string key, std::string inputi)
{
  vector<char> buf;    //= new vector<uint8_t>();
  vector<char> outstr; // = new vector<uint8_t>();
  size_t inpsize = (inputi.size() - 6) / 3;
  char tchar;
  for (auto a : inputi)
    tchar = a;
  cout<<endl;
  string input = htos(inputi, inpsize);
  buf.reserve(inpsize + 1);
  set_up(buf, input);
  outstr.reserve(inpsize - 27);
  cmd_dec((uint8_t *)((&buf)->data()), inpsize, (uint8_t *)((&outstr)->data()), key);
  cout << "Decryption complete: " << endl;
  std::ostringstream outt;
  stringstream ss;
  string str="";
  for (size_t i = 0; i < inpsize -28; i++)
  {
    str.append(1,(char)outstr[i]);
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
  string u1="mike";
  string u2="a_longer_name";
  cout << "Value1: \n";
  getline(cin, u1);
  string a = stoh(u1, u1.size());
  string b = htos(a, a.size());
  printf("Hex %s\n", a.data());
  printf("Back to string %s\n", b.data());
  return 0;
  // string k="1234";
  // string v="";
  // cout << "Value: \n";
  // getline(cin, v);
  // std::cout<<"Hash: " << get_hash(v)<<std::endl;
  // std::string a="";
  // a = loader_check(k, v);

  // std::cout<<"\nWe got: "<<a<<std::endl;
  // std::string b ="";
  // b= loader_out(k, a);
  // std::cout << "\nDec we got: " << b << std::endl;
  // return 0;
}
#endif //END_TEST

#ifdef __EMSCRIPTEN__
EMSCRIPTEN_BINDINGS(raw_pointers) {
  emscripten::register_vector<uint8_t>("CharList");
  emscripten::function("loader_check", &loader_check);
  emscripten::function("loader_out", &loader_out);
  emscripten::function("get_hash",&get_hash);
  emscripten::function("pp_hash",&pp_hash);
}
#endif


#endif //EMPP_CPP