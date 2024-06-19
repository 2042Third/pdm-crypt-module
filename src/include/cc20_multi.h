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
#include <thread>
#elif FOURCORE
#else
#endif

#define BLOCK_SIZE  4608000
/* Invariant: BLOCK_SIZE % 64 == 0
               115200, 256000, 576000, 1152000,2304000,4608000,6912000,9216000 ...
               Block size*/

// The poly1305 mac key size
#define POLY_SIZE 16

//
/**
 * The nonce size
 * chacha20     => 12
 * xchacha20    => 24
 * */
#define NONCE_SIZE 24
#define CC20_KEY_SIZE 32
#define XNONCE_SIZE 16

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
  /**
   * Configs for runtime encryption
   * Theses are the defaults
   * */
  struct config {
    int poly1305_toggle=1; // be changed into enum or structrure
    int ENABLE_SHA3_OUTPUT = 0; 
    int DISPLAY_PROG =1;
    int final_line_written = 0; // Whether or not the fianl line is written
    int DE=0;
    int pure_xor=0;
    int arg_c=1;
    int core_id=-1;
    int core_count = 8;
  };
}

class Cc20;

namespace PDM_BRIDGE_MOBILE {
  void ck_crypt(uint8_t* buf, size_t input_length, uint8_t*outstr,  uint8_t*nonce, const uint8_t*key,size_t offset=0);
  void ck_enc(uint8_t* buf, size_t input_length, uint8_t* outstr , const std::string& text_key);
  void ck_dec(uint8_t* buf, size_t input_length, uint8_t* outstr , const std::string& text_key);
  void cmd_enc(const uint8_t* buf, size_t input_length, uint8_t* outstr , const uint8_t* _key);
  void cmd_dec(const uint8_t* buf, size_t input_length, uint8_t* outstr , const uint8_t* _key);
}

namespace PDM_MEM_SIDE_CHANNEL {
  void crypt_x_times(uint8_t* buf, size_t input_length, uint8_t*outstr,  uint8_t*nonce
                     , const uint8_t*key,size_t offset=0, size_t x=1);

}

class Cc20{

public:


  /**
   * ########### From defines at the top of this file
   * */
#ifndef SINGLETHREADING
#include <thread>
  int THREAD_COUNT = 4;
#elif FOURCORE
  int THREAD_COUNT = 4;
#else
  int THREAD_COUNT = 4;
#endif


  /**
   * ########### End defines at the top of this file
   * */

  /**
   * ########### From defines at the top of the cpp file
   * */

/**
 * Moved "BLOCK_SIZE" to header file
 * Moved "THREAD_COUNT" to header file and made it definied at compile-time.
 * */
// const int PER_THREAD_BACK_LOG = 0; // This is not enabled.


// Statically allocates, and uses BLOCK_SIZE*THREAD_COUNT of memory.
// char thread_track[THREAD_COUNT][BLOCK_SIZE] = {{0}};


/**
 * Need to change this into an object
 * */
  std::vector<long int> writing_track; // Tells the writer thread how much to read; should only be different on the last block.

  std::vector<size_t> progress_bar; //size_t progress_bar[THREAD_COUNT];

//  std::vector<std::vector<unsigned long int>> arg_track;
/* Passes arguments into threads.
                                       arg_track[THREAD_COUNT][0] ---> Thread number
                                       arg_track[THREAD_COUNT][1] ---> NOT USED
                                       arg_track[THREAD_COUNT][2] ---> NOT USED
                                       arg_track[THREAD_COUNT][3] ---> Remaining plain size
                                       arg_track[THREAD_COUNT][4] ---> NOT USED*/


#ifndef SINGLETHREADING
  std::vector<std::thread> threads; // std::thread threads[THREAD_COUNT];
#endif // SINGLETHREADING

  /**
   * ########### End defines at the top of the cpp file
   * */

/**
 *  -- replaces cc20_parts
 * Should contain all things a thread needs, including the encryption
 * */
  struct worker {
    void set(int thread_number, uint8_t* linew0, size_t num_need,
             uint8_t * xline, uint64_t xcount, Cc20* _ptr);
    void set_core(int _coreId);
//  void x_set(int thrd, uint8_t* linew0, size_t n,  uint8_t * line, Cc20 * ptr);
    void multi_enc_pthrd();
//  void x_multi_enc_pthrd();
    unsigned long int thrd;
    uint8_t* line;
    uint8_t* linew1;
    uint64_t count;
    size_t n;
    Cc20 * ptr;
    int coreId;
  };
  void start_seq();
  void encr(uint8_t*line,uint8_t*linew,unsigned long int fsize);
  void rd_file_encr(uint8_t* buf, std::string oufile_name, size_t outsize) ;
  void rd_file_encr(const std::string file_name, uint8_t* outstr) ;
  void rd_file_encr (const uint8_t * buf, uint8_t* outstr, size_t input_length);
  void rd_file_encr (const std::string file_name, std::string oufile_name);

  void stream( uint8_t*plain,unsigned int len);
  void set_vals(uint8_t * nonce0, uint8_t*key0);
  void h_set_vals( uint8_t * nonce0, const uint8_t * key0);
  void x_set_vals( uint8_t *nonce0, const uint8_t *key0);

  void one_block (int thrd, uint64_t xcount);

  static void endicha(uint8_t *a, uint32_t *b);
  void set_configurations (c20::config configs);
  void read_original_mac(unsigned char * m, uint8_t* input_file, size_t off);
  int check_file(std::string a);
  int file_written(){return FILE_WRITTEN;}
  std::string get_dec_loc(std::string file_name);
  void get_key_hash(std::string a, uint8_t* hash);
  char* get_inp_nonce (std::string infile_name, uint8_t* line1);
  void get_time_diff(std::chrono::time_point<std::chrono::high_resolution_clock> start);
  void get_key_hash(const uint8_t* a, uint8_t* hash);
  int is_dec(){return conf.DE;}
  explicit Cc20(int _thread_count_ = 8 );
  ~Cc20();
  void reset_poly();
  void end_cleanup();
  void clean_worker();
  static void display_progress(size_t n, const size_t* progress_bar, int THREAD_COUNT);


  cc20_poly* poly;// should be in private
  SHA3 hashing;
  std::vector<Cc20*> arg_ptr; // Parent pointers for each thread.

  std::vector<std::vector<uint8_t>> nex; // uint8_t nex[THREAD_COUNT][65];
  std::vector<worker*> arg_track; // worker* arg_track[THREAD_COUNT];
  c20::config conf;
  uint8_t key_orig[CC20_KEY_SIZE]={0}; // Only used in wasm.
protected:
  // A copy of a state.
  // Tracks all the input
  uint8_t * key;

  // Binary constant for chacha20 state, modified 
  const unsigned long b1 =  0B01100001011100010111100011100101 ;
  const unsigned long b2 =  0B10110111001011000110011101101110 ;
  const unsigned long b3 =  0B01111001111000101010110100110010 ;
  const unsigned long b4 =  0B01101011001001000110010101110100 ;
  int FILE_WRITTEN =0;
  uint64_t count;
  std::vector<std::vector<uint32_t>> cy; // uint32_t cy[THREAD_COUNT][17];
  std::vector<std::vector<uint32_t>> folow; // uint32_t folow[THREAD_COUNT][17];
  char *linew;
  uint8_t * nonce;
  uint8_t nonce_orig[NONCE_SIZE]={0};
  unsigned char orig_mac[16]={0};

};

std::string htos (std::string a);
std::string stoh (std::string a);
void cmd_enc(uint8_t* buf, std::string oufile_name, std::string text_key, size_t outsize);
void cmd_enc(std::string infile_name, std::string oufile_name, std::string text_nonce);
void cmd_enc(std::string infile_name, uint8_t* outstr, std::string text_key);
void cmd_enc(std::string infile_name, std::string oufile_name, c20::config configs);
void display_progress(size_t n);
void cmd_enc(std::string infile_name, std::string oufile_name, std::string text_nonce, c20::config configs);
void cmd_enc(uint8_t* buf, size_t input_length, uint8_t* outstr , std::string text_key);
void cmd_dec(uint8_t* buf, size_t input_length, uint8_t* outstr , std::string text_key);
void cmd_enc_s(const uint8_t* buf, size_t input_length, uint8_t* outstr , const uint8_t* _key, size_t _key_size);
void cmd_dec_s(const uint8_t* buf, size_t input_length, uint8_t* outstr , const uint8_t* _key, size_t _key_size);
#endif