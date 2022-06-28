//
// Created by Yi Yang on 6/26/2022.
//

#include "xCc20.h"

#include <errno.h>
#include <fcntl.h>
#ifndef SINGLETHREADING
#include <thread>
#endif //SINGLETHREADING
#include <iomanip>
#include <numeric>
#include <memory>
#include <filesystem>
#include <unistd.h>
#include <sstream>
#include <string.h>
#include "cc20_file.h"
#ifndef PDM_CC20_DEV_HPP
#include "cc20_dev.hpp"
#endif // PDM_CC20_DEV_HPP

#include <functional> // std::ref

using namespace std;

xCc20 * xarg_ptr[THREAD_COUNT]; // Parent pointers for each thread.
/**
 * Need to change this into an object
 * */
long int writing_track[THREAD_COUNT]; // Tells the writer thread how much to read; should only be different on the last block.

size_t progress_bar[THREAD_COUNT];
#ifndef SINGLETHREADING
thread xthreads[THREAD_COUNT]; // xThreads
#endif // SINGLETHREADING

// Sets the encryption is for encryption or decryption.

/*
    XOR's two objects begaining at s1's off for n.
    And beginging at s2's 0 for n.

*/

template < typename NU >
void set_xor(NU * s1, NU * s2, std::ofstream s3, unsigned int n, unsigned int off) {
  for (unsigned int i = 0; i < n; i++) {
    s3 << s1[i + off] ^ s2[i];
  }
}


/**
 * XChaCha20 read file and encrypt
 * */
void xCc20::x_rd_file_encr(const std::string file_name, std::string oufile_name) {
  const uint8_t * line;
  cc20_file r_file;
  r_file.read_new(file_name.data());
#ifdef VERBOSE
  cout << "Staring file size " << (size_t) r_file.file_size() << endl;
  #if defined(_WIN64)
  cout << "_WIN64 defined" <<endl;
  #else
  cout << "_WIN64 not defined" << endl;
  #endif
  cout << "nonce size: "<< XNONCE_SIZE <<endl;

#endif

  r_file.write_new(oufile_name.data(),1);
#ifdef VERBOSE
  cout << "poly bool : "<< conf.poly1305_toggle <<endl;
  cout << "decryption bool : "<< conf.DE <<endl;
#endif
  if(conf.DE){

#ifdef VERBOSE
    cout << "decryption size : "<< r_file.file_size()-XNONCE_SIZE-POLY_SIZE <<endl;
#endif
    if(conf.poly1305_toggle )
      linew = r_file.get_write_mapping(r_file.file_size()-XNONCE_SIZE-POLY_SIZE); // Mapped writting
    else
      linew = r_file.get_write_mapping(r_file.file_size()-XNONCE_SIZE); // Mapped writting
  }
  else { // Encryption step

#ifdef VERBOSE
    cout << "encryption size : "<< r_file.file_size()+XNONCE_SIZE+POLY_SIZE <<endl;
#endif
    if(conf.poly1305_toggle )
      linew = r_file.get_write_mapping(r_file.file_size()+XNONCE_SIZE+POLY_SIZE); // Mapped writting
    else
      linew = r_file.get_write_mapping(r_file.file_size()+XNONCE_SIZE); // Mapped writting
  }
  line = (const uint8_t*) r_file.get_mapping();
  x_rd_file_encr((uint8_t*)line, (uint8_t*)linew, r_file.file_size());
  r_file.unmap();
  if (conf.ENABLE_SHA3_OUTPUT && this->file_written()) cout <<"SHA3: \""<<hashing.getHash()<<"\""<<endl;
}

void xCc20::x_rd_file_encr(uint8_t * buf, uint8_t* outstr, std::size_t input_length) {

#ifdef VERBOSE
  cout << "Main x_rd_file_encr " <<endl;
#endif
  std::size_t n = 0;
  const uint8_t * line;
  line = buf;
  this->linew = (char *) outstr;
  if(!conf.DE){
    std::copy(this->xnonce_orig, this->xnonce_orig + XNONCE_SIZE, this->linew);
    this->linew =this->linew+XNONCE_SIZE;
  }

#ifdef VERBOSE
  cout << "nonce : "<< xnonce_orig<<endl;
#endif
  n = input_length;
  std::size_t ttn = input_length;
  std::size_t tn = 0;
  if(conf.DE && conf.poly1305_toggle){ // when decrypting
    n-=POLY_SIZE;
    ttn-=POLY_SIZE;
  }
  uint32_t count = 0;
  for (long int i = 0; i < THREAD_COUNT; i++) {
    writing_track[i] = 0;
  }
  unsigned long int tracker = 0;
  unsigned long int np = 0;
  if(conf.DE){
    ttn-=XNONCE_SIZE;
    n-=XNONCE_SIZE;
    line=line+XNONCE_SIZE;
    // Read original mac
    if(conf.poly1305_toggle)
      read_original_mac(orig_mac, (unsigned char *)line, (std::size_t)ttn);
  }
#ifndef SINGLETHREADING
  thread progress;
  if (conf.DISPLAY_PROG){
    for (unsigned int i=0; i<THREAD_COUNT;i++){
      progress_bar[i] = 0;
    }
    progress = thread(display_progress,ttn);
  }
#endif// SINGLETHREADING
  // cout << "Size: "<<ttn << endl;
#ifdef VERBOSE
  cout <<this->linew<<endl;
#endif
#ifdef VERBOSE
  cout << "before first arg track "<<this->linew<<endl;
#endif
  xarg_track[np % THREAD_COUNT]->x_set(np % THREAD_COUNT,(uint8_t*)this->linew, n, (uint8_t*)line,  this->count, this);
#ifndef SINGLETHREADING
  xthreads[np % THREAD_COUNT] = thread( &xCc20::xworker::x_multi_enc_pthrd,xarg_track[np % THREAD_COUNT]) ;
#else
  xarg_track[np % THREAD_COUNT]->multi_enc_pthrd();
#endif // SINGLETHREADING
  np++;
  for (unsigned long int k = 0; k < ((unsigned long int)(ttn / 64) + 0); k++) { // If leak, try add -1
    if (n >= 64) {
      tracker += 64;
      if (tn % (BLOCK_SIZE) == 0 && (k != 0)) {
#ifndef SINGLETHREADING
        // waiting for thread to finish
        if (xthreads[np % THREAD_COUNT].joinable()) {
          xthreads[np % THREAD_COUNT].join();
        }
#ifdef VERBOSE
        cout << "[main] " <<np % THREAD_COUNT<< " regular being dispatched"<< endl;
#endif
        xarg_track[np % THREAD_COUNT]->x_set(np % THREAD_COUNT,(uint8_t*)this->linew+tn,  n, (uint8_t*)line + tn,this->count+1, this);
        xthreads[np % THREAD_COUNT] = thread( &xCc20::xworker::x_multi_enc_pthrd,xarg_track[np % THREAD_COUNT]) ;
        tracker = 0;
        np++;
#else
        xarg_track[0]->set(0,(uint8_t*)this->linew+tn,  n, (uint8_t*)line + tn, count + 1, this);
        xarg_track[0]->multi_enc_pthrd();
        tracker = 0;
        np++;
#endif// SINGLETHREADING
      }
    }
    else {
#ifndef SINGLETHREADING
      if (xthreads[np % THREAD_COUNT].joinable() && conf.final_line_written != 1) {
        xthreads[np % THREAD_COUNT].join();
      }
      xarg_track[np % THREAD_COUNT]->x_set(np % THREAD_COUNT,(uint8_t*)this->linew+tn,  n,  (uint8_t*)line + tn,this->count+1, this);
      xthreads[np % THREAD_COUNT] = thread( &xCc20::xworker::x_multi_enc_pthrd,xarg_track[np % THREAD_COUNT]) ;
#else
      xarg_track[0]->set(0,(uint8_t*)this->linew+tn,  n,  (uint8_t*)line + tn, count + 1, this);
      xarg_track[0]->multi_enc_pthrd();
#endif// SINGLETHREADING
    }
    count += 1;
    n -= 64;
    tn += 64;
  }

#ifndef SINGLETHREADING
  for (int i = 0; i < THREAD_COUNT; i++) {
    if (xthreads[i].joinable()){
      xthreads[i].join();
    }
  }
#endif// SINGLETHREADING
  // Check encryption correctness
  if(conf.poly1305_toggle){
    if(!conf.DE)
      poly->update((unsigned char *)linew,ttn);
    else
      poly->update((unsigned char *)line,ttn);
  }
  unsigned char mac[POLY_SIZE]={0};
  poly->finish((unsigned char*)mac);
  if (poly->verify(mac, orig_mac)
      || !this->conf.DE
      || !this->conf.poly1305_toggle
      ){
    if (conf.ENABLE_SHA3_OUTPUT){
      if(!conf.DE)
        hashing.add(line,ttn );
      else
        hashing.add(linew,ttn );
    }

    if(!conf.DE && conf.poly1305_toggle)
      std::copy(mac, mac + POLY_SIZE, linew + ttn);
    FILE_WRITTEN=1;
  }
  else {
    cout << "Password incorrect, decryption failed and no files written..."<<endl;
  }
#ifndef SINGLETHREADING
  if(conf.DISPLAY_PROG){
    if (progress.joinable())
      progress.join();
  }
#endif// SINGLETHREADING
}
/*
 * for xchacha20
    Given nonce is already set, one_block takes the thrd number and the block count and
    modifies nex[thrd] for the next block of chacha20.


*/

void xCc20::xone_block(int thrd, uint32_t count) {
  cy[thrd][12] = count;
  memcpy(folow[thrd], cy[thrd], sizeof(uint32_t) * POLY_SIZE);
#ifdef ROUNDCOUNTTWLV
  for (unsigned int i = 0; i < 6; i++) tworounds(folow[thrd]); // 12 rounds
#else
  for (unsigned int i = 0; i < 10; i++) tworounds(folow[thrd]); // 20 rounds
#endif
  set_conc(cy[thrd], folow[thrd], POLY_SIZE);
  endicha(this -> nex[thrd], cy[thrd]);
}
/**
 * Sets up the xchacha20 initial state.
 * Given H ChaCha20 is already setup
 *
 * */
void xCc20::x_set_vals(uint8_t *nonce0, uint8_t *key0) {
  h_set_vals(nonce0,key0); // This is really one of the only things needed to change, but oh well...
  this -> nonce = nonce0;
  copy(nonce,nonce+NONCE_SIZE,this -> nonce_orig );
  this -> count = 0;
  for (unsigned int i = 0; i < THREAD_COUNT; i++) {
    // x chacha subkey setup
    cy[i][4] = cy[i][0];
    cy[i][5] = cy[i][1];
    cy[i][6] = cy[i][2];
    cy[i][7] = cy[i][3];
    cy[i][8] = cy[i][12];
    cy[i][9] = cy[i][13];
    cy[i][10] = cy[i][14];
    cy[i][11] = cy[i][15];

    this -> cy[i][0] = 0x61707865;
    this -> cy[i][1] = 0x3320646e;
    this -> cy[i][2] = 0x79622d32;
    this -> cy[i][3] = 0x6b206574;

    expan(this -> cy[i], 13, this -> nonce+23, 3); //
    expan(this -> cy[i], 4, key0, 8);
    //algo change #2
    xone_block((int)i, (int)1);
//    p_state(cy[i]);
  }
}
/**
 * HChaCha20 initialize
 *  Nonce needs to be 16 bytes, comparing to 12 bytes in ChaCha20
 * */
void xCc20::h_set_vals(uint8_t * nonce0, uint8_t * key0) {
  this -> nonce = nonce0;
  std::copy(nonce, nonce + XNONCE_SIZE, this -> xnonce_orig );
  this -> count = 0;
  for (unsigned int i = 0; i < THREAD_COUNT; i++) {
    this -> cy[i][0] = 0x61707865;
    this -> cy[i][1] = 0x3320646e;
    this -> cy[i][2] = 0x79622d32;
    this -> cy[i][3] = 0x6b206574;

    expan(this -> cy[i], 12, this -> nonce, 4);
    expan(this -> cy[i], 4, key0, 8);
    xone_block((int)i, (int)1);
  }
}


void xCc20::xworker::x_multi_enc_pthrd() {
  size_t tracker = 0; // Used
  xCc20 * ptr = xarg_ptr[xthrd];

#ifdef VERBOSE
  cout<<"[calc] "<<xthrd<<" locks, starting write " << endl;
#endif
  for (size_t k = 0; k < BLOCK_SIZE / 64; k++) {
    ptr -> xone_block((int) xthrd, this->count); // change to time 64 , Jun/28/2022
    if (xn >= 64) { //
      for (long int i = 0; i < 64; i++) {
        xlinew1[i + tracker] = (char)(xline[i + tracker] ^ ptr -> nex[xthrd][i]);
      }
      tracker += 64;
      if (tracker >= (BLOCK_SIZE)) { // Notifies the writing tread when data can be read
        writing_track[xthrd] = tracker;
        tracker = 0;
      }
    } else {
      for (size_t i = 0; i < xn; i++) {
        xlinew1[i+tracker] = (char)(xline[i + tracker] ^ ptr -> nex[xthrd][i]);
      }
      tracker += xn;
      writing_track[xthrd] = tracker; // Notifies the writing tread when data can be read
      break;
    }
    count += 1;
    xn -= 64;
    if(ptr->conf.DISPLAY_PROG)progress_bar[xthrd]+=64;

  }
#ifdef VERBOSE
  cout<<"[calc] "<<xthrd<<" unlocks " << endl;
#endif
}
/**
 * XChaCha20
 * */
void xCc20::xworker::x_set(size_t thrd_in, uint8_t* linew0, size_t n_in, uint8_t * line, uint32_t xcount,xCc20 * ptr) {
  // xarg_track[thrd_in].thrd_in = thrd_in;
  // xarg_track[thrd_in].linew = linew1;
  // xarg_track[thrd_in].n_in = n_in;
  // xarg_track[thrd_in].line = line;
  // xarg_track[thrd_in].count = count;

  this->xthrd = thrd_in;
  this->xlinew1 = linew0;
  this->xn = n_in;
  this->xline = line;
  this->count = xcount*BLOCK_SIZE; // changed to time block size , Jun/28/2022

  xarg_ptr[thrd_in] = ptr;
}

char* xCc20::xget_inp_nonce(std::string infile_name, uint8_t* line1){
  FILE * infile = fopen(infile_name.data(), "rb");
  fread(line1,sizeof(char), XNONCE_SIZE,infile);
  fclose(infile);
  if(line1!=NULL)
    return (char*)line1;
  else
    return nullptr;
}

xCc20::xCc20() {
  poly = new cc20_poly();
  for (unsigned int i=0 ; i< THREAD_COUNT; i++){
    xarg_track[i]=new xworker();
    for (unsigned int f = 0; f< POLY_SIZE+1;f++){
      folow[i][f] = {0};
      cy[i][f] = {0};
    }
  }
}
xCc20::~xCc20() {
  if(poly !=NULL) delete poly;
  for (unsigned int i=0 ; i< THREAD_COUNT;i++){
    delete xarg_track[i];
  }
}


/**
 * xchacha20 file to file encryption
 * */
void x_cmd_enc(string infile_name, string oufile_name, string text_nonce, c20::config configs){
  uint8_t key_hash[65]= {0};
  uint8_t inonce [XNONCE_SIZE+1] = {0};
  xCc20 cry_obj;
#ifndef WEB_RELEASE
  if (!cry_obj.check_file(infile_name))
    return;
#endif// WEB_RELEASE
  cry_obj.set_configurations(configs);
  string text_key;
  cout << "Password:" << endl;
  std::getline(std::cin, text_key);
  cout<< cry_obj.conf.DE<<endl;
  cry_obj.get_key_hash(text_key, key_hash);
  string infile_name_copy=infile_name+".pdm";
  if(cry_obj.is_dec()){
    text_nonce = cry_obj.xget_inp_nonce(infile_name_copy, inonce);
    text_nonce = pad_to_key((string) text_nonce, XNONCE_SIZE);
  }

#ifdef VERBOSE
  cout << "before setval nonce: "<< text_nonce <<endl;
#endif
  std::chrono::time_point<std::chrono::high_resolution_clock> start = std::chrono::high_resolution_clock::now();
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t*)key_hash);
  cry_obj.poly->init((unsigned char *)key_hash);
  if(cry_obj.is_dec()){
    cry_obj.x_rd_file_encr(infile_name_copy,cry_obj.get_dec_loc(infile_name));
  }
  else {
    cry_obj.x_rd_file_encr(infile_name, infile_name+".pdm");
  }
  cry_obj.get_time_diff(start);
}
