/*
cc20_multi.cpp

pdm/Personal Data Management system is a encrypted and multiplatform data searching, building, archiving tool.
This is the encryption core module for pdm.

author:     Yi Yang
            5/2021
*/



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
#include "cc20_multi.h"

#include <functional> // std::ref

using namespace std;

// void enc_writing(string oufile_name);
// void enc_writing_nw();
// void multi_enc_pthrd(int thrd);
// void multi_enc_pthrd_nw(int thrd);
// void set_thread_arg(unsigned long int thrd, uint8_t* linew1, size_t n,  uint8_t * line, uint32_t count, Cc20 * ptr) ;
// void set_thread_arg(unsigned long int thrd, uint8_t* np,unsigned long int tracker,unsigned long int n, unsigned long int tn,uint8_t* line,uint32_t count, Cc20 * ptr);
       


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
long int writing_track[THREAD_COUNT]; // Tells the writer thread how much to read; should only be different on the last block.

size_t progress_bar[THREAD_COUNT];



// unsigned long int arg_track[THREAD_COUNT][6];
/* Passes arguments into threads.
                                       arg_track[THREAD_COUNT][0] ---> Thread number
                                       arg_track[THREAD_COUNT][1] ---> NOT USED
                                       arg_track[THREAD_COUNT][2] ---> NOT USED
                                       arg_track[THREAD_COUNT][3] ---> Remaining plain size
                                       arg_track[THREAD_COUNT][4] ---> NOT USED*/



Cc20 * arg_ptr[THREAD_COUNT]; // Parent pointers for each thread.

#ifndef SINGLETHREADING
thread threads[THREAD_COUNT]; // Threads
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

/*
    Given nonce is already set, one_block takes the thrd number and the block count and 
    modifies nex[thrd] for the next block of chacha20.

    This doesn't track whether or not the count is increamented; thus, to ensure security
    please increament the count before passing it into one_block

*/

void Cc20::one_block(int thrd, uint32_t count) {
  cy[thrd][12] = count;
  memcpy(folow[thrd], cy[thrd], sizeof(uint32_t) * 16);
  #ifdef ROUNDCOUNTTWLV
  for (unsigned int i = 0; i < 6; i++) tworounds(folow[thrd]); // 8 rounds
  #else
  for (unsigned int i = 0; i < 10; i++) tworounds(folow[thrd]); // 20 rounds
  #endif
  set_conc(cy[thrd], folow[thrd], 16);
  endicha(this -> nex[thrd], cy[thrd]);
}

/**
 * Takes input and output file names.
 * Writes the encrypted/decrypted content to the output file.
 * */
void Cc20::rd_file_encr(const std::string file_name, string oufile_name) {
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
  #endif
  r_file.write_new(oufile_name.data(),1);
  if(conf.DE){
    if(conf.poly1305_toggle )
      linew = r_file.get_write_mapping(r_file.file_size()-12-16); // Mapped writting
    else
      linew = r_file.get_write_mapping(r_file.file_size()-12); // Mapped writting
  }
  else { // Encryption step
    if(conf.poly1305_toggle )
      linew = r_file.get_write_mapping(r_file.file_size()+12+16); // Mapped writting
    else
      linew = r_file.get_write_mapping(r_file.file_size()+12); // Mapped writting
  }
  line = (const uint8_t*) r_file.get_mapping();
  rd_file_encr((uint8_t*)line, (uint8_t*)linew, r_file.file_size());
  r_file.unmap();
  if (conf.ENABLE_SHA3_OUTPUT && this->file_written()) cout <<"SHA3: \""<<hashing.getHash()<<"\""<<endl;
}

/**
 * string to hex
 * */
string stoh (string a){
  string out;
  out.reserve(a.size () / (2 * sizeof (string)));
  (void) hex_from (a,std::back_inserter(out));
  return out;
}


/**
 * Hex to String 
 * 
 * Based on boost and sql function that converts a hex string 
 **/
  string htos (string a) {
    string out;
    out.reserve(a.size () / (2 * sizeof (string)));
    (void) htos_to(a,std::back_inserter(out));
    return out;
  }

/**
 * Takes a file name and outputs the encrypted/decrypted content.
 *   
  #ifdef VERBOSE
  cout << "Staring file size " << (size_t) r_file.file_size() << endl;
  #if defined(_WIN64)
  cout << "_WIN64 defined" <<endl;
  #else
  cout << "_WIN64 not defined" << endl;
  #endif
  #endif

  #ifdef VERBOSE
  cout << "File mapped " << line[0] << endl;
  #endif
 * */
void Cc20::rd_file_encr(const std::string file_name, uint8_t* outstr) {
  const uint8_t * line; 
  cc20_file r_file;
  r_file.read_new(file_name.data());
  line = (const uint8_t*) r_file.get_mapping();
  rd_file_encr((uint8_t*)line, (uint8_t*)outstr, r_file.file_size());
  r_file.unmap();
  if (conf.ENABLE_SHA3_OUTPUT && this->file_written()) cout <<"SHA3: \""<<hashing.getHash()<<"\""<<endl;
}
/**
 * Takes a memroy output file.
 * */
void Cc20::rd_file_encr(uint8_t* buf, string oufile_name, size_t outsize) {
  cc20_file r_file;
  r_file.write_new(oufile_name.data(),1);
  if(conf.poly1305_toggle )
    linew = r_file.get_write_mapping(r_file.file_size()+12+16); // Mapped writting
  else 
    linew = r_file.get_write_mapping(r_file.file_size()+12); // Mapped writting
  rd_file_encr((uint8_t*)buf, (uint8_t*)linew, outsize);
  if (conf.ENABLE_SHA3_OUTPUT && this->file_written()) cout <<"SHA3: \""<<hashing.getHash()<<"\""<<endl;
}

/*
    Creates one thread for writing and THREAD_COUNT threads for calculating the 
    cypher text. It also handles disk mapping for reading, and opens oufile for 
    writing. After, it will dispatch threads when there are vacancy in threads[].
    Returns when all plain is read, and all threads are joined.

*/

void Cc20::rd_file_encr(uint8_t * buf, uint8_t* outstr, size_t input_length) {
  size_t n = 0;
  const uint8_t * line; 
  line = buf;
  this->linew = (char *) outstr;
  if(!conf.DE){
    copy(this->nonce_orig, this->nonce_orig+12,this->linew);
    this->linew =this->linew+12;
  }
  n = input_length;
  size_t ttn = input_length;
  size_t tn = 0;
  if(conf.DE && conf.poly1305_toggle){ // when decrypting
    n-=16;
    ttn-=16;
  }
  uint32_t count = 0;
  for (long int i = 0; i < THREAD_COUNT; i++) {
    writing_track[i] = 0;
  }
  unsigned long int tracker = 0;
  unsigned long int np = 0;
  if(conf.DE){
    ttn-=12;
    n-=12;
    line=line+12;
    // Read original mac
    if(conf.poly1305_toggle)
      read_original_mac(orig_mac, (unsigned char *)line, (size_t)ttn);
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
  arg_track[np % THREAD_COUNT]->set(np % THREAD_COUNT,(uint8_t*)this->linew, n, (uint8_t*)line, count, this);
  #ifndef SINGLETHREADING
  threads[np % THREAD_COUNT] = thread( &Cc20::worker::multi_enc_pthrd,arg_track[np % THREAD_COUNT]) ;
  #else
  arg_track[np % THREAD_COUNT]->multi_enc_pthrd();
  #endif // SINGLETHREADING
  np++;
  for (unsigned long int k = 0; k < ((unsigned long int)(ttn / 64) + 0); k++) { // If leak, try add -1
    if (n >= 64) {
      tracker += 64;
      if (tn % (BLOCK_SIZE) == 0 && (k != 0)) {
  #ifndef SINGLETHREADING
        // waiting for thread to finish
        if (threads[np % THREAD_COUNT].joinable()) {
          threads[np % THREAD_COUNT].join();
        }
        #ifdef VERBOSE
        cout << "[main] " <<np % THREAD_COUNT<< " regular being dispatched"<< endl;
        #endif
        arg_track[np % THREAD_COUNT]->set(np % THREAD_COUNT,(uint8_t*)this->linew+tn,  n, (uint8_t*)line + tn, count + 1, this);
        threads[np % THREAD_COUNT] = thread( &Cc20::worker::multi_enc_pthrd,arg_track[np % THREAD_COUNT]) ;
        tracker = 0;
        np++;
  #else 
        arg_track[0]->set(0,(uint8_t*)this->linew+tn,  n, (uint8_t*)line + tn, count + 1, this);
        arg_track[0]->multi_enc_pthrd();
        tracker = 0;
        np++;
  #endif// SINGLETHREADING
      }
    } 
    else {
  #ifndef SINGLETHREADING
      if (threads[np % THREAD_COUNT].joinable() && conf.final_line_written != 1) {
        threads[np % THREAD_COUNT].join();
      }
      arg_track[np % THREAD_COUNT]->set(np % THREAD_COUNT,(uint8_t*)this->linew+tn,  n,  (uint8_t*)line + tn, count + 1, this);
      threads[np % THREAD_COUNT] = thread( &Cc20::worker::multi_enc_pthrd,arg_track[np % THREAD_COUNT]) ;
  #else 
      arg_track[0]->set(0,(uint8_t*)this->linew+tn,  n,  (uint8_t*)line + tn, count + 1, this);
      arg_track[0]->multi_enc_pthrd(); 
  #endif// SINGLETHREADING
    }
    count += 1;
    n -= 64;
    tn += 64;
  }
  
  #ifndef SINGLETHREADING
  for (int i = 0; i < THREAD_COUNT; i++) {
    if (threads[i].joinable()){
      threads[i].join();
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
  unsigned char mac[16]={0};
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
      copy(mac,mac+16,linew+ttn);
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

/**
 * Displays progress
 * -- move to namespace
 * */
void display_progress(size_t n) {
  unsigned int current=0;
  size_t acum=0;
  unsigned int res =50;
  double num =0;
  string line, spaces;
  char progress_buffer[100];
  while(current<res ){
    acum=0;
    sprintf(progress_buffer,"[%s%s]%.1f%%\0",line.data(), spaces.data(), ((num*100)-100));
    cout << progress_buffer << "\r";
    num = (float)accumulate(progress_bar,progress_bar+THREAD_COUNT,acum)/n;
    if((num) *res>=current || n<1000){
      current++;
    }
    line="";
    spaces="";
    num+=1;
    for(unsigned i =0 ; i<res;i++){
      if (i<=current)
        line+="-";
      else
        spaces+=" ";
    }
    usleep(10000);
  }
  printf("[%s%s]%.1f%% \n",line.data(), spaces.data(), ((100.0)));
}

/*
    Sets arguments in arg_track for threads.

*/
void Cc20::worker::set(int thrd, uint8_t* linew0, size_t n,  uint8_t * line, uint32_t count, Cc20 * ptr) {
  // arg_track[thrd].thrd = thrd;
  // arg_track[thrd].linew = linew1;
  // arg_track[thrd].n = n;
  // arg_track[thrd].line = line;
  // arg_track[thrd].count = count;

  this->thrd = thrd;
  this->linew1 = linew0;
  this->n = n;
  this->line = line;
  this->count = count;

  arg_ptr[thrd] = ptr;
}

// auto thread_func = [](int &i) {
//     return i+42;
// };

void Cc20::worker::multi_enc_pthrd() {
  size_t tracker = 0; // Used
  Cc20 * ptr = arg_ptr[thrd];

  #ifdef VERBOSE
          cout<<"[calc] "<<thrd<<" locks, starting write " << endl;
  #endif
  for (size_t k = 0; k < BLOCK_SIZE / 64; k++) {
    ptr -> one_block((int) thrd, (int) count);
    if (n >= 64) {
      for (long int i = 0; i < 64; i++) {
        linew1[i + tracker] = (char)(line[i + tracker] ^ ptr -> nex[thrd][i]);
      }
      tracker += 64;
      if (tracker >= (BLOCK_SIZE)) { // Notifies the writing tread when data can be read
        writing_track[thrd] = tracker;
        tracker = 0;
      }
    } else {
      for (size_t i = 0; i < n; i++) {
        linew1[i+tracker] = (char)(line[i + tracker] ^ ptr -> nex[thrd][i]);
      }
      tracker += n;
      writing_track[thrd] = tracker; // Notifies the writing tread when data can be read
      break;
    }
    count += 1;
    n -= 64;
    if(ptr->conf.DISPLAY_PROG)progress_bar[thrd]+=64;
  }
  #ifdef VERBOSE
          cout<<"[calc] "<<thrd<<" unlocks " << endl;
  #endif
}


void Cc20::set_vals(uint8_t * nonce0, uint8_t * key0) {
  this -> nonce = nonce0;
  copy(nonce,nonce+12,this -> nonce_orig );
  this -> count = 0;
  for (unsigned int i = 0; i < THREAD_COUNT; i++) {
    // this -> cy[i][0] = 0x617178e5;
    // this -> cy[i][1] = 0xb72c676e;
    // this -> cy[i][2] = 0x79e2ad32;
    // this -> cy[i][3] = 0x6b246574;

    this -> cy[i][0] = 0x61707865;
    this -> cy[i][1] = 0x3320646e;
    this -> cy[i][2] = 0x79622d32;
    this -> cy[i][3] = 0x6b206574;

    expan(this -> cy[i], 13, this -> nonce, 3);
    expan(this -> cy[i], 4, key0, 8);
    //algo change #2
    one_block((int)i, (int)1);
  }
}

void Cc20::endicha(uint8_t * a, uint32_t * b) {
  for (unsigned int i = 0; i < 16; i++) {
    U32T8_S(a + 4 * i, b[i]);
  }
}

/**
 * Get the location of the decrypted file 
 * */
std::string Cc20::get_dec_loc(std::string file_name){
  size_t indx = file_name.find_last_of('/');
  if(indx == std::string::npos)
    indx = file_name.find_last_of('\\');
  return file_name.insert(indx+1, "dec-");;
}

void Cc20::read_original_mac(unsigned char * m, uint8_t* input_file, size_t off){
  for (unsigned int i=0 ; i< 16; i++){
    m[i]=input_file[off+i];
  }
}

/**
 * Constructor
 * */
Cc20::Cc20(){
  poly = new cc20_poly();
  for (unsigned int i=0 ; i< THREAD_COUNT; i++){
    arg_track[i]=new worker();
    for (unsigned int f = 0; f< 17;f++){
      folow[i][f] = {0};
      cy[i][f] = {0};
    }
  } 
}

void Cc20::set_configurations(c20::config configs){
  conf.poly1305_toggle = configs.poly1305_toggle;
  conf.ENABLE_SHA3_OUTPUT = configs.ENABLE_SHA3_OUTPUT;
  conf.DISPLAY_PROG = configs.DISPLAY_PROG;
  conf.final_line_written = configs.final_line_written;
  conf.DE = configs.DE;
}
int Cc20::check_file (string a){
  std::filesystem::path f{ a };
  if ((std::filesystem::file_size(f) < 150000000) && conf.DISPLAY_PROG ) // Default to disable progress display if less than 150 mb
    conf.DISPLAY_PROG=0;
  if (!std::filesystem::exists(f)){
    cout<<"File not found \'"<<a<<"\'"<<endl;
    return 0;
  }
  return 1;
}

void Cc20::get_key_hash(string a, uint8_t* hash){
  SHA3 key_hash;
  key_hash.add(stob(a).data(),a.size());
  key_hash.add(stob(a).data(),a.size());
  cout<<"key hash size "<< key_hash.getHash().size()<<endl;
  memcpy(hash, key_hash.getHash().data(), sizeof(uint8_t) * 64);
}

char* Cc20::get_inp_nonce(string infile_name, uint8_t* line1){
  FILE * infile = fopen(infile_name.data(), "rb");
  fread(line1,sizeof(char), 12,infile);
  fclose(infile);
  if(line1!=NULL)
    return (char*)line1;
  else 
    return nullptr;
}

void Cc20::get_time_diff(  std::chrono::time_point<std::chrono::high_resolution_clock> start){
  auto end = std::chrono::high_resolution_clock::now();
  auto dur = end - start;
  auto i_millis = std::chrono::duration_cast < std::chrono::milliseconds > (dur);
  auto f_secs = std::chrono::duration_cast < std::chrono::duration < float >> (dur);
  if(this->file_written() )
    printf("\n%.2fs\n",f_secs.count());
}
/**
 * Init encryption.
 * This version of pdm-crypt have different ways to interfacing the data.
 * It can be mapped from hard drive and output as a mapped file, or take a file
 * and output a memory pointer, or input and output memory pointers of the data.
 * 
 * * * deprecated comment * * * *  
 * This version of pdm-crypt interfaces within memory, which means 
 * entire file will be read before the encryption. 
 * Thus, this version is not recommended for large files (more than half 
 * of your computer's memory).
 * For a memory effecient version, please use a history version (that version 
 * uses at most ~320 mb for an arbitrary-size file).
 * * * deprecated comment end * * * * 
 *  
 * @param infile_name input file name
 * @param oufile_name output file name
 * @param nonce the nonce of this encryption
 * 
 * */
void cmd_enc(string infile_name, string oufile_name, string text_nonce, c20::config configs){
  uint8_t key_hash[65]= {0};
  uint8_t inonce [13] = {0}; 
  Cc20 cry_obj;
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
    text_nonce = cry_obj.get_inp_nonce(infile_name_copy, inonce);
    text_nonce = pad_to_key((string) text_nonce, 12);
  }
  std::chrono::time_point<std::chrono::high_resolution_clock> start = std::chrono::high_resolution_clock::now();
  cry_obj.set_vals((uint8_t*)text_nonce.data(), (uint8_t*)key_hash);
  cry_obj.poly->init((unsigned char *)key_hash); 
  if(cry_obj.is_dec()){
    cry_obj.rd_file_encr(infile_name_copy,cry_obj.get_dec_loc(infile_name));
  }
  else {
    cry_obj.rd_file_encr(infile_name, infile_name+".pdm");
  }
  cry_obj.get_time_diff(start);
}

/**
 * Takes a file, outputs memory.
 * Generates the nonce.
 * Takes the key
 * 
 * */
void cmd_enc(string infile_name, uint8_t* outstr, std::string text_key){
  Cc20 cry_obj;
#ifndef WEB_RELEASE
  if (!cry_obj.check_file(infile_name))
    return;
#endif// WEB_RELEASE
  Bytes key;
  Bytes nonce;
  string text_nonce;
  SHA3 key_hash;
  key_hash.add(stob(text_key).data(),text_key.size());
  key_hash.add(stob(text_key).data(),text_key.size());
  string infile_name_copy;
  if(cry_obj.conf.DE){
    uint8_t *line1[13]={0};
    infile_name_copy = infile_name+".pdm";
    FILE * infile = fopen(infile_name_copy.data(), "rb");
    fread(line1,sizeof(char), 12,infile);
    if(line1!=NULL)
      text_nonce=(char*)line1;
    fclose(infile);
  }
  else {
    init_byte_rand_cc20(nonce,12);
    text_nonce = btos(nonce);
  }
  if (text_nonce.size() != 0) {
    text_nonce = pad_to_key((string) text_nonce, 12);
  }

  cry_obj.set_vals((uint8_t*)text_nonce.data(), (uint8_t *)key_hash.getHash().data());
  cry_obj.poly->init((unsigned char *)key_hash.getHash().data()); 
  if(cry_obj.conf.DE){
    cry_obj.rd_file_encr(infile_name_copy,outstr);
  }
  else {
    cry_obj.rd_file_encr(infile_name, outstr);
  }
}


/**
 * Takes a memory, outputs file.
 * Generates the nonce.
 * Takes the key
 * 
 * */
void cmd_enc(uint8_t* buf, string oufile_name, std::string text_key, size_t outsize){
  
  Cc20 cry_obj;
  // cry_obj.DE = cryDE;
  Bytes key;
  Bytes nonce;
  string text_nonce;
  SHA3 key_hash;
  key_hash.add(stob(text_key).data(),text_key.size());
  key_hash.add(stob(text_key).data(),text_key.size());
  string infile_name_copy;
  uint8_t line1[13]={0};
  if(cry_obj.conf.DE){
    for (unsigned int i=0;i<12;i++)
      line1[i]=(buf[i]);
    text_nonce=(char*)line1;
  }
  else {
    init_byte_rand_cc20(nonce,12);
    text_nonce = btos(nonce);
  }
  if (text_nonce.size() != 0) {
    text_nonce = pad_to_key((string) text_nonce, 12);
  }

  cry_obj.set_vals((uint8_t*)text_nonce.data(), (uint8_t *)key_hash.getHash().data());
  cry_obj.poly->init((unsigned char *)key_hash.getHash().data()); 
  if(cry_obj.conf.DE){
    cry_obj.rd_file_encr(buf,oufile_name, outsize );
  }
  else {
    cry_obj.rd_file_encr(buf,oufile_name, outsize);
  }
}

// EMSCRIPTEN_KEEPALIVE
void cmd_enc(uint8_t* buf, size_t input_length, uint8_t* outstr , string text_key){
  // cout<<"[cc20_multi] encryption start."<<endl;
  Bytes cur;
  init_byte_rand_cc20(cur,12);
  string text_nonce = btos(cur);
  Cc20  cry_obj;
        cry_obj.conf.DE=0;
        cry_obj.conf.DISPLAY_PROG=0;
  SHA3  key_hash;
        key_hash.add(stob(text_key).data(),text_key.size());
        key_hash.add(stob(text_key).data(),text_key.size());
  cry_obj.poly->init((unsigned char *)key_hash.getHash().data()); 
  if (text_nonce.size() != 0) {
    text_nonce = pad_to_key((string) text_nonce, 12);
  }
  cry_obj.set_vals((uint8_t*)text_nonce.data(), (uint8_t *)key_hash.getHash().data());
  cry_obj.rd_file_encr(buf, outstr, input_length);
}

// EMSCRIPTEN_KEEPALIVE 
void cmd_dec(uint8_t* buf, size_t input_length, uint8_t* outstr , string text_key){
  // cout<<"[cc20_multi] decryption start."<<endl;
  // string text_nonce ;
  Cc20  cry_obj;
        cry_obj.conf.DE=1;
        cry_obj.conf.DISPLAY_PROG=0;
  SHA3  key_hash;
        key_hash.add(stob(text_key).data(),text_key.size());
        key_hash.add(stob(text_key).data(),text_key.size());
  cry_obj.poly->init((unsigned char *)key_hash.getHash().data()); 
  Bytes input_vc;
  for(size_t i=0 ; i<12;i++)
    input_vc.push_back(buf[i]);
  string text_nonce = btos(input_vc);
  if (text_nonce.size() != 0) {
    text_nonce = pad_to_key((string) text_nonce, 12);
  }
  cry_obj.set_vals((uint8_t*)text_nonce.data(), (uint8_t *)key_hash.getHash().data());
  if(cry_obj.conf.DE){
    cry_obj.rd_file_encr(buf,outstr, input_length);
  }
  else {
    cry_obj.rd_file_encr(buf, outstr, input_length);
  }
}


void set_config(char*inp, c20::config * sts){
  string a = inp;
  for(unsigned int i=0;i<a.size();i++){
    if      (a[i] == 'S' ) sts->ENABLE_SHA3_OUTPUT = 1;
    else if (a[i] == 'H' ) sts->DISPLAY_PROG = 0;
    else if (a[i] == 'd' ) sts->poly1305_toggle = 0;
    else if (a[i] == 'E' ) sts->DE = 0;
    else if (a[i] == 'D' ) sts->DE = 1;
    else if (a[i] == 'h'){
      printf("Usage: %s\nOptions:\n-d\t%s\n-S\t%s\n-H\t%s\n-E\t%s\n-D\t%s\n-h\t%s\n%s\n",
        "c20 [OPTIONS] FILE_NAME",
        "Fast mode, disable poly1305 checking",
        "Enable sha3 output on plain text",
        "Hide progress bar",
        "Encrypt(default)",
        "Decrypt",
        "Help menu (current)",
        "Personal Data Manager Encryption Module\nWarning: This program overwrittes files with .pdm extension, make sure you are not overwritting unintended files by mistake! \nby Yi Yang, 2021");
      exit(0);
    }
    else if (a[i]!='-') {
      printf("Unrecognized option \"%c\", -h for help",a[i]);
    }
  }
}



c20::config rd_inp(unsigned int argc, char ** argv, string *infile){
  c20::config sts;
  for (unsigned int i = 1; i< argc;i++){
    if (argv[i][0] == '-'){
      set_config(argv[i], &sts);
    }
    else{
      if (infile->empty()){
        sts.arg_c++;
        *infile = argv[i];
      }
      else
        return sts;
    }
  }
  
  return sts;
}

Cc20::~Cc20() {
  if(poly !=NULL) delete poly;
  for (unsigned int i=0 ; i< THREAD_COUNT;i++){
    delete arg_track[i];
  }
}

#ifdef HAS_MAIN 

int main(int argc, char ** argv) {
  string infile,oufile,nonce;
  c20::config configs = rd_inp(argc,argv,&infile);
  if (configs.arg_c!=2){
    cout<<"Must have 1 file input, -h for help."<<endl;
    return 0;
  }
  Bytes cur ;
  init_byte_rand_cc20(cur,12);
  nonce="1";
  cmd_enc(infile,"",btos(cur), configs);
  return 0;
}
#endif
