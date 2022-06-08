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

#ifndef SINGLETHREADING
#define THREAD_COUNT 20
#elif FOURCORE
#define THREAD_COUNT 4 
#else
#define THREAD_COUNT 1 
#endif

#define BLOCK_SIZE  4608000
/* Invariant: BLOCK_SIZE % 64 == 0
               115200, 256000, 576000, 1152000,2304000,4608000,6912000,9216000 ...
               Block size*/

#include <stdio.h>
#include <chrono>
// Added 
// #ifndef WINDOWS
// #endif
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/types.h>
#include "cc20_poly.hpp"
#include "sha3.h"


namespace c20{
  struct config {
    int poly1305_toggle=1; // be changed into enum or structrure
    int ENABLE_SHA3_OUTPUT = 0; 
    int DISPLAY_PROG =1;
    int final_line_written = 0; // Whether or not the fianl line is written
    int DE=0; 
    int arg_c=1;
  };
}

class Cc20{
  /**
   *  -- replaces cc20_parts
   * Should contain all things a thread needs, including the encryption 
   * */
  struct worker {
    void set(int thrd, uint8_t* linew0, size_t n,  uint8_t * line, uint32_t count, Cc20 * ptr);
    void multi_enc_pthrd();
    unsigned long int thrd;
    uint8_t* line;
    uint8_t* linew1;
    uint32_t count;
    size_t n;
  };

public:

  void start_seq();
  void encr(uint8_t*line,uint8_t*linew,unsigned long int fsize);
  void rd_file_encr(uint8_t* buf, std::string oufile_name, size_t outsize) ;
  void rd_file_encr(const std::string file_name, uint8_t* outstr) ;
  void rd_file_encr (uint8_t * buf, uint8_t* outstr, size_t input_length);
  void rd_file_encr (const std::string file_name, std::string oufile_name);
  void stream( uint8_t*plain,unsigned int len);
  void set_vals(uint8_t * nonce0, uint8_t*key0);
  void one_block (int thrd, uint32_t count);
  void endicha(uint8_t *a, uint32_t *b);
  void set_configurations (c20::config configs);
  void read_original_mac(unsigned char * m, uint8_t* input_file, size_t off);
  int check_file(std::string a);
  int file_written(){return FILE_WRITTEN;}
  std::string get_dec_loc(std::string file_name);
  void get_key_hash(std::string a, uint8_t* hash);
  char* get_inp_nonce (std::string infile_name, uint8_t* line1);
  void get_time_diff(std::chrono::time_point<std::chrono::high_resolution_clock> start);

  uint8_t nex[THREAD_COUNT][65];
  int is_dec(){return conf.DE;}
  Cc20();
  ~Cc20();

  cc20_poly* poly;// should be in private
  SHA3 hashing; 
  worker* arg_track[THREAD_COUNT];
  c20::config conf;
private:
  unsigned char orig_mac[16]={0};
  uint32_t folow[THREAD_COUNT][17]; // A copy of a state.
  char *linew; // Tracks all the input
  int FILE_WRITTEN =0;  
  uint8_t * nonce;
  uint32_t count;
  uint8_t nonce_orig[13]={0};
  uint32_t cy[THREAD_COUNT][17];
  uint8_t * key;

  // Binary constant for chacha20 state, modified 
  const unsigned long b1 =  0B01100001011100010111100011100101 ;
  const unsigned long b2 =  0B10110111001011000110011101101110 ;
  const unsigned long b3 =  0B01111001111000101010110100110010 ;
  const unsigned long b4 =  0B01101011001001000110010101110100 ;
};
std::string htos (std::string a);
std::string stoh (std::string a);
void cmd_enc(uint8_t* buf, std::string oufile_name, std::string text_key, size_t outsize);
void cmd_enc(std::string infile_name, std::string oufile_name, std::string text_nonce);
void cmd_enc(std::string infile_name, uint8_t* outstr, std::string text_key);
void display_progress(size_t n);
void cmd_enc(uint8_t* buf, size_t input_length, uint8_t* outstr , std::string text_key);
void cmd_dec(uint8_t* buf, size_t input_length, uint8_t* outstr , std::string text_key);
#endif