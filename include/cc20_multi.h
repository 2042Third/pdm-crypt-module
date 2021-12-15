/*
cc20_multi.h

pdm/Personal Data Management system is a encrypted and multiplatform data searching, building, archiving tool.

author:     Yi Yang
            5/2021
*/
#ifndef _cc20_multi_
#define _cc20_multi_

#ifdef WEB_RELEASE
#undef HAS_MAIN
#endif//WEB_RELEASE

#ifdef DESKTOP_RELEASE
#undef HAS_MAIN
#endif//DESKTOP_RELEASE

#include <stdio.h>
#include <chrono>
// Added 
// #ifndef WINDOWS
// #endif
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/types.h>

// using namespace std;

class Cc20{


public:

  void start_seq();
  void encr(uint8_t*line,uint8_t*linew,unsigned long int fsize);
  void rd_file_encr(uint8_t* buf, std::string oufile_name, size_t outsize) ;
  void rd_file_encr(const std::string file_name, uint8_t* outstr) ;
  void rd_file_encr (uint8_t * buf, uint8_t* outstr, size_t input_length);
  void rd_file_encr (const std::string file_name, std::string oufile_name);
  void stream( uint8_t*plain,unsigned int len);
  void set_vals(uint8_t * nonce, uint8_t*key);
  void one_block (int thrd, uint32_t count);
  void endicha(uint8_t *a, uint32_t *b);
  void read_original_mac(unsigned char * m, uint8_t* input_file, size_t off);
  int file_written(){return FILE_WRITTEN;}
  std::string get_dec_loc(std::string file_name);
  // void display_progress(unsigned int n) ;
  int DE = 0;

  #ifdef SINGLETHREADING
  // Make sure this number is same as THREAD_COUNT
  //           *
  uint8_t nex[30][65];
  #else
  uint8_t nex[1][65];
  #endif
  
  ~Cc20();

private:
  // cc20_file* r_file = NULL;
  int FILE_WRITTEN =0;  
  uint8_t * nonce;

  uint32_t count;

  uint8_t nonce_orig[13]={0};
  #ifdef SINGLETHREADING
  // Make sure this number is same as THREAD_COUNT
  //          *
  uint32_t cy[30][17];
  #else
  uint32_t cy[1][17];
  #endif
  

  uint8_t * key;

  // Binary constant for chacha20 state, modified 
  unsigned long b1 =  0B01100001011100010111100011100101 ;
  unsigned long b2 =  0B10110111001011000110011101101110 ;
  unsigned long b3 =  0B01111001111000101010110100110010 ;
  unsigned long b4 =  0B01101011001001000110010101110100 ;
};

void cmd_enc(uint8_t* buf, std::string oufile_name, std::string text_key, size_t outsize);
void cmd_enc(std::string infile_name, std::string oufile_name, std::string text_nonce);
void cmd_enc(std::string infile_name, uint8_t* outstr, std::string text_key);
void display_progress(size_t n);
// EMSCRIPTEN_KEEPALIVE
void cmd_enc(uint8_t* buf, size_t input_length, uint8_t* outstr , std::string text_key);

// EMSCRIPTEN_KEEPALIVE
void cmd_dec(uint8_t* buf, size_t input_length, uint8_t* outstr , std::string text_key);
#endif