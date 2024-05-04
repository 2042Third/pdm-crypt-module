//
// Created by Yi Yang on 12/9/2022.
//

#include "cc20_dev.h"
#ifdef VERBOSE
#include <iostream>
#endif
#include <random>

//template<typename NU>
//void cc20_dev::set_conc(NU* s1,NU* s2,unsigned int n){
//  for(unsigned int i=0;i<n;i++)s1[i]+=s2[i];
//}

namespace cc20_dev{
template<typename NU>
void set_xor(NU* s1,NU* s2,unsigned int n,unsigned int off){
  for(unsigned int i=0;i<n;i++){
    s1[i+off]=s1[i+off]^s2[i];
  }
}

// Convert c++ string into Bytes type
Bytes stob (std::string &src){
  Bytes vec(src.begin(), src.end());
  return vec;
}

/**
 * Also copies exists in stand_alone.cpp
 * */
std::string btos (Bytes &src){
  std::string str(src.begin(), src.end());
  return str;
}

/**
 * Also copies exists in stand_alone.cpp
 * */
void init_byte_rand_cc20 (Bytes & a, int n){
  for (int i=0;i<n;i++) {
    std::random_device rd;   // non-deterministic generator
    std::mt19937 gen(rd());
    a.push_back((uint8_t) gen());
  }
}

std::string pad_to_key (const std::string& text_key, const int len){
#ifdef VERBOSE
  std::cout<<"pad to key length: "<<text_key.size()<<std::endl;
#endif
  std::string key;
  key = std::string((len - text_key.size()), '0');
  key = key+text_key;
  return key;
}

uint32_t upper(uint64_t a){
  uint32_t b;
  a&= 0xffffffff00000000ull;
  b=a>>32;
  return b;
}
uint32_t lower(uint64_t a){
  uint32_t b;
  a&= 0x00000000ffffffffull;
  a=a<<32;
  b=a>>32;
  return (uint32_t)b;
}
void expan(uint32_t * ot, unsigned int off, const uint8_t* in, unsigned int n) {
  for(unsigned int i=0;i<n;i++){
    ot[off+i] = U8T32_S(in+4*i);
  }
}


// Operate a quarter-round chacha state on total of 16 bytes or 4 32-bit numbers at a time.
void quarteround(uint32_t * x, uint32_t a, uint32_t b, uint32_t c, uint32_t d){

  x[a] += x[b];
  x[d] = rotl32(x[d] ^ x[a], 16);
  x[c] += x[d];
  x[b] = rotl32(x[b] ^ x[c], 12);
  x[a] += x[b];
  x[d] = rotl32(x[d] ^ x[a], 8);
  x[c] += x[d];
  x[b] = rotl32(x[b] ^ x[c], 7);
}

void tworounds(uint32_t * state){
  quarteround(state, 0, 4, 8, 12) ;
  quarteround(state, 1, 5, 9, 13) ;
  quarteround(state, 2, 6, 10, 14);
  quarteround(state, 3, 7, 11, 15);
  quarteround(state, 0, 5, 10, 15);
  quarteround(state, 1, 6, 11, 12);
  quarteround(state, 2, 7, 8, 13) ;
  quarteround(state, 3, 4, 9, 14) ;
}
} // namespace cc20_dev