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
#include <pthread.h>
#endif //SINGLETHREADING
#include <iomanip>
#include <numeric>
#include <memory>
#ifndef ANDROID
#include <filesystem>
#endif
#include <unistd.h>
#include <sstream>
#include <cstring>
#include "cc20_file.h"
#include <cc20_dev.h>
#include "cc20_multi.h"
#include "cc20_scrypt.h"
#include "crypto_rand.hpp"
//#include "xCc20.h"

#include <functional> // std::ref
#include <utility>
#include <fstream>

#ifdef __APPLE__
#include <mach/thread_act.h>
#endif // __apple__

using namespace std;





static void helper_print_stats(const uint8_t* a,size_t size,int binary=1) {
    std::string ac ; ac.resize(size); memcpy(ac.data(),a,size);
    std::cout<< "Size : \""<<ac.size()<<"\""<<std::endl;
    if(!binary)std::cout<< "Plain: "<<ac<<std::endl;
    std::cout<< " Hax : \""<<stoh(ac)<<"\""<<std::endl;
    SHA3 vh;
    vh.add(a,size);
    string b = vh.getHash();
    std::cout<< "Hash : \""<<b<<"\""<<std::endl;
  }

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
    Given nonce is already set, one_block takes the thrd number and the block xcount and
    modifies nex[thrd] for the next block of chacha20.

    This doesn't track whether or not the xcount is increamented; thus, to ensure security
    please increament the xcount before passing it into one_block

*/

void Cc20::one_block(int thrd, uint64_t xcount) {
  cy[thrd][12] = cc20_dev::upper(xcount);
  cy[thrd][13] = cc20_dev::lower(xcount);
  copy(cy[thrd].begin(), cy[thrd].end(), folow[thrd].begin()); // memcpy(folow[thrd], cy[thrd], sizeof(uint32_t) * 16);

#ifdef ROUNDCOUNTTWLV
  for (unsigned int i = 0; i < 6; i++) tworounds(&folow[thrd][0]); // 12 rounds
#else
  for (unsigned int i = 0; i < 10; i++) cc20_dev::tworounds(&folow[thrd][0]); // 20 rounds
#endif

  cc20_dev::set_conc(&cy[thrd][0], &folow[thrd][0] , 16);
  endicha( &nex[thrd][0], &cy[thrd][0]);
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
  printf("file size: %llu\n",r_file.file_size());
  #if defined(_WIN64)
  cout << "_WIN64 defined" <<endl;
  #else
  cout << "_WIN64 not defined" << endl;
  #endif
#endif
  r_file.write_new(oufile_name.data(),1);
  if(conf.DE){
    if(conf.poly1305_toggle )
      linew = r_file.get_write_mapping(r_file.file_size()-NONCE_SIZE-POLY_SIZE); // Mapped writting
    else
      linew = r_file.get_write_mapping(r_file.file_size()-NONCE_SIZE); // Mapped writting
  }
  else { // Encryption step
    if(conf.poly1305_toggle )
      linew = r_file.get_write_mapping(r_file.file_size()+NONCE_SIZE+POLY_SIZE); // Mapped writting
    else
      linew = r_file.get_write_mapping(r_file.file_size()+NONCE_SIZE); // Mapped writting
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
    linew = r_file.get_write_mapping(r_file.file_size()+NONCE_SIZE+POLY_SIZE); // Mapped writting
  else 
    linew = r_file.get_write_mapping(r_file.file_size()+NONCE_SIZE); // Mapped writting
  rd_file_encr((uint8_t*)buf, (uint8_t*)linew, outsize);
  if (conf.ENABLE_SHA3_OUTPUT && this->file_written()) cout <<"SHA3: \""<<hashing.getHash()<<"\""<<endl;
}

/*
    Creates one thread for writing and THREAD_COUNT threads for calculating the 
    cypher text. It also handles disk mapping for reading, and opens oufile for 
    writing. After, it will dispatch threads when there are vacancy in threads[].
    Returns when all plain is read, and all threads are joined.

*/

void Cc20::rd_file_encr(const uint8_t * buf, uint8_t* outstr,  size_t input_length) {
  size_t n = 0;
  const uint8_t * line;
  line = buf;
  this->linew = (char *) outstr;
  if(!conf.DE && !conf.pure_xor){
    copy(this->nonce_orig, this->nonce_orig+NONCE_SIZE,this->linew);
    this->linew =this->linew+NONCE_SIZE;
  }
  n = input_length;
  size_t ttn = input_length;
  size_t tn = 0;
  if(conf.DE && conf.poly1305_toggle){ // when decrypting
    n-=POLY_SIZE;
    ttn-=POLY_SIZE;
  }
  uint64_t count = 0;
  for (long int i = 0; i < THREAD_COUNT; i++) {
    writing_track[i] = 0;
  }
  unsigned long int tracker = 0;
  unsigned long int np = 0;
  if(conf.DE){
    ttn-=NONCE_SIZE;
    n-=NONCE_SIZE;
    line=line+NONCE_SIZE;
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
    progress = thread(display_progress,ttn, progress_bar.data(), THREAD_COUNT);
  }
#endif// SINGLETHREADING
  // cout << "Size: "<<ttn << endl;

  arg_ptr[np % THREAD_COUNT] = this;
  arg_track[np % THREAD_COUNT]->set(np % THREAD_COUNT,(uint8_t*)this->linew, n
                                    , (uint8_t*)line, count, this);
  arg_track[np % THREAD_COUNT]->set_core(conf.core_id);
#ifndef SINGLETHREADING
  threads[np % THREAD_COUNT] = thread( &Cc20::worker::multi_enc_pthrd,arg_track[np % THREAD_COUNT]) ;
#else
  arg_track[np % THREAD_COUNT]->multi_enc_pthrd();
#endif // SINGLETHREADING
  np++;
#ifdef VERBOSE
  cout << "[rd_file_encr] setup complete, starting main loop"<< endl;
#endif
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
        arg_ptr[np % THREAD_COUNT] = this;
        arg_track[np % THREAD_COUNT]->set(np % THREAD_COUNT,(uint8_t*)this->linew+tn
                                          ,  n, (uint8_t*)line + tn, count + 1, this);
        arg_track[np % THREAD_COUNT]->set_core(conf.core_id);
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
    else if (n>0) {
#ifdef VERBOSE
      cout << "[main] " <<np % THREAD_COUNT<< " end thread being dispatched"<< endl;
#endif
#ifndef SINGLETHREADING
      if (threads[np % THREAD_COUNT].joinable() && conf.final_line_written != 1) {
        threads[np % THREAD_COUNT].join();
      }
      arg_ptr[np % THREAD_COUNT] = this;
      arg_track[np % THREAD_COUNT]->set(np % THREAD_COUNT,(uint8_t*)this->linew+tn,  n
                                        ,  (uint8_t*)line + tn, count + 1, this);
      arg_track[np % THREAD_COUNT]->set_core(conf.core_id);
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
      copy(mac,mac+POLY_SIZE,linew+ttn);
    FILE_WRITTEN=1;
  }
  else {
    cout << "Password incorrect, decryption failed and no files written..."<<endl;
  }

  end_cleanup();

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
void Cc20::display_progress(size_t n, const size_t* progress_bar, int THREAD_COUNT) {
#ifndef WEB_RELEASE
  const unsigned int bar_width = 50;
  const unsigned int update_interval = 100000; // 100ms

  size_t total_progress = 0;
  size_t last_size = 0;
  int count = 0;
  double progress_percentage = 0.0;
  std::string progress_line(bar_width, ' ');

  auto last_update_time = std::chrono::steady_clock::now();

  do {
    total_progress = 0;
    for (int i = 0; i < THREAD_COUNT; ++i) {
      total_progress += progress_bar[i];
    }

    progress_percentage = (static_cast<double>(total_progress) / n) * 100.0;
    auto current_time = std::chrono::steady_clock::now();
    auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(current_time - last_update_time);

    if (elapsed_time.count() >= update_interval || progress_percentage >= 100.0) {
      int filled_width = static_cast<int>(progress_percentage * bar_width / 100.0);
      std::fill_n(progress_line.begin(), filled_width, '-');

      std::cout << "\r[" << progress_line << "] " << std::fixed << std::setprecision(1)
                << progress_percentage << "%" << std::flush;

      if (progress_percentage >= 100.0) {
        std::cout << std::endl;
        return;
      }

      last_update_time = current_time;
      last_size = total_progress;
      if (last_size == total_progress) {
        count++;
      } else {
        count = 0;
      }

      if (count >= 10) {
        std::cout << std::endl;
        return;
      }
    }

    std::this_thread::sleep_for(std::chrono::microseconds(1000)); // Sleep for 1ms
  } while (total_progress+10 < n);

  std::cout << std::endl;
#endif
}

/*
    Sets arguments in arg_track for threads.

*/
void Cc20::worker::set(int thread_number, uint8_t* linew0, size_t num_need, uint8_t * xline, uint64_t xcount, Cc20* _ptr) {
  this->thrd = thread_number;
  this->linew1 = linew0;
  this->n = num_need;
  this->line = xline;
  this->count = xcount * BLOCK_SIZE;
  ptr = _ptr;
}

void Cc20::worker::set_core(int _coreId) {
  coreId = _coreId;
}

// auto thread_func = [](int &i) {
//     return i+42;
// };

void Cc20::worker::multi_enc_pthrd() {
  size_t tracker = 0; // Used

  // If it is in linux check if you can set core id
#ifdef __linux__
  if (coreId!=-1) {
    // Set the affinity of the thread to the specified core
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    CPU_SET(coreId, &cpuSet);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuSet);
  }
#elif defined(_WIN64)
  if (coreId!=-1) {
    // Set the affinity of the thread to the specified core
    SetThreadAffinityMask(GetCurrentThread(), 1 << coreId);
  }
#elif defined(__APPLE__)


#endif // __linux__
#ifndef SINGLETHREADING
  if (coreId!=-1) {
    // Set the affinity of the thread to the specified core
    thread_affinity_policy_data_t policy = { (int)coreId };
    thread_policy_set(pthread_mach_thread_np(pthread_self()),
                      THREAD_AFFINITY_POLICY,
                      (thread_policy_t)&policy,
                      THREAD_AFFINITY_POLICY_COUNT);
  }
#endif // SINGLETHREADING
#ifdef VERBOSE
  cout<<"[calc] "<<thrd<<" locks, starting write " << endl;
#endif
  for (size_t k = 0; k < BLOCK_SIZE / 64; k++) {
    ptr -> one_block((int) thrd, count);

    if (n >= 64) {
      for (long int i = 0; i < 64; i++) {
        linew1[i + tracker] = (char)(line[i + tracker] ^ ptr -> nex[thrd][i]);
      }
      tracker += 64;
      if (tracker >= (BLOCK_SIZE)) { // Notifies the writing tread when data can be read
        ptr->writing_track[thrd] = tracker;
        tracker = 0;
      }
    } else {
      for (size_t i = 0; i < n; i++) {
        linew1[i+tracker] = (char)(line[i + tracker] ^ ptr -> nex[thrd][i]);
      }
      tracker += n;
      ptr->writing_track[thrd] = tracker; // Notifies the writing tread when data can be read
      break;
    }
    count += 1;
    n -= 64;
    if(ptr->conf.DISPLAY_PROG)ptr->progress_bar[thrd]+=64;
  }
#ifdef VERBOSE
  cout<<"[calc] "<<thrd<<" unlocks " << endl;
#endif
}


/**
 * ChaCha20 initialize
 * */
void Cc20::set_vals(uint8_t * nonce0, uint8_t * key0) {
  this -> nonce = nonce0;
  copy(nonce,nonce+NONCE_SIZE,this -> nonce_orig );
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

    cc20_dev::expan(&this -> cy[i][0], 13, this -> nonce, 3);
    cc20_dev::expan(&this -> cy[i][0], 4, key0, 8);
    //algo change #2
    one_block((int)i, (int)1);
  }
}

/**
 * Sets up the xchacha20 initial state.
 * Given H ChaCha20 is already setup
 *
 * */
void Cc20::x_set_vals(uint8_t *nonce0, const uint8_t *key0) {
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

    cc20_dev::expan(&this -> cy[i][0], 14, this -> nonce+16, 2); // * explained below
    cc20_dev::expan(&this -> cy[i][0], 4, key0, 8);
    cy[i][12]=0;
    cy[i][13]=1;  // originally nonce is only at index 13,14,15
                  // , now the nonce is generating the xchacha-subkey
                  // ; thus, only last 8 bytes of the 24 bytes can be used for
                  // nonce, prefixed by a null or 1 (this line)
    //algo change #2
    one_block((int)i, (int)1);
  }
}
/**
 * HChaCha20 initialize
 *  Nonce needs to be 16 bytes, comparing to 12 bytes in ChaCha20
 * */
void Cc20::h_set_vals( uint8_t * nonce0, const uint8_t * key0) {
  this -> nonce = nonce0;
  std::copy(nonce, nonce + NONCE_SIZE, this -> nonce_orig );
  this -> count = 0;
  for (unsigned int i = 0; i < THREAD_COUNT; i++) {
    this -> cy[i][0] = 0x61707865;
    this -> cy[i][1] = 0x3320646e;
    this -> cy[i][2] = 0x79622d32;
    this -> cy[i][3] = 0x6b206574;
    cc20_dev::expan(&this -> cy[i][0], 12, this -> nonce, 4);
    cc20_dev::expan(&this -> cy[i][0], 4, key0, 8);
    one_block((int)i, (int)1);

  }
}

void Cc20::endicha(uint8_t * a, uint32_t * b) {
  for (unsigned int i = 0; i < POLY_SIZE; i++) {
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
  for (unsigned int i=0 ; i< POLY_SIZE; i++){
    m[i]=input_file[off+i];
  }
}

/**
 * Constructor
 * */
Cc20::Cc20(int _thread_count_): THREAD_COUNT(_thread_count_){
#ifdef VERBOSE
  cout<<"[Cc20 Constructor] _thread_count_ = "<<_thread_count_<<" . " << endl;
#endif
#ifndef WEB_RELEASE
  threads.resize(THREAD_COUNT);
#endif // WEB_RELEASE
  writing_track.resize(THREAD_COUNT);
  progress_bar.resize(THREAD_COUNT);
  arg_ptr.resize(THREAD_COUNT);


  cy.resize(THREAD_COUNT, std::vector<uint32_t>(17));

  folow.resize(THREAD_COUNT, std::vector<uint32_t>(17));

  nex.resize(THREAD_COUNT, std::vector<uint8_t>(65));

  arg_track.resize(THREAD_COUNT);

  poly = new cc20_poly();

  for (unsigned int i=0 ; i< THREAD_COUNT; i++){
    arg_track[i] = new worker();
    for (unsigned int f = 0; f< POLY_SIZE+1;f++){
      folow[i][f] = {0};
      cy[i][f] = {0};
    }
  }
#ifdef VERBOSE
  cout<<"[Cc20 Constructor] Exites. " << endl;
#endif
}

Cc20::~Cc20() {
  delete poly;
  for (auto & i : arg_track){
    delete i;
  }
}


void Cc20::set_configurations(c20::config configs){
  conf.poly1305_toggle = configs.poly1305_toggle;
  conf.ENABLE_SHA3_OUTPUT = configs.ENABLE_SHA3_OUTPUT;
  conf.DISPLAY_PROG = configs.DISPLAY_PROG;
  conf.final_line_written = configs.final_line_written;
  conf.DE = configs.DE;
  conf.core_id = configs.core_id;
}
int Cc20::check_file (string a){
#ifdef ANDROID
  return 0;
#else
  std::filesystem::path f{ a };
  if ((std::filesystem::file_size(f) < 150000000) && conf.DISPLAY_PROG ) // Default to disable progress display if less than 150 mb
    conf.DISPLAY_PROG=0;
  if (!std::filesystem::exists(f)){
    cout<<"File not found \'"<<a<<"\'"<<endl;
    return 0;
  }
  return 1;
#endif
}
/**
 * Helper of cc20.
 * Yeah, it makes the key.
 * */
void Cc20::get_key_hash(string a, uint8_t* hash){
  c20_scrypt k;
  string key_hash;
  key_hash.reserve(32);
  k.make_ps((const uint8_t *)a.data(),hash);
}
/**
 * Helper of cc20.
 * Yeah, it makes the key.
 * */
void Cc20::get_key_hash(const uint8_t* a, uint8_t* hash){
  c20_scrypt k;
  string key_hash;
  key_hash.reserve(32);
  k.make_ps(a,hash);
}

char* Cc20::get_inp_nonce(string infile_name, uint8_t* line1){
  FILE * infile = fopen(infile_name.data(), "rb");
  fread(line1,sizeof(char), NONCE_SIZE,infile);
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
  uint8_t inonce [NONCE_SIZE] = {0};
  Cc20 cry_obj;
#ifndef WEB_RELEASE
  if (!cry_obj.check_file(infile_name))
    return;
#endif// WEB_RELEASE
  cry_obj.set_configurations(configs);
  string text_key;
  cout << "Password:" << endl;
  std::getline(std::cin, text_key);
  cry_obj.get_key_hash(text_key, key_hash);
  string infile_name_copy=infile_name+".pdm";
  if(cry_obj.is_dec()){
    text_nonce = cry_obj.get_inp_nonce(infile_name_copy, inonce);
    text_nonce = text_nonce.substr(0,24);//pad_to_key((string) text_nonce.substr(0,24), NONCE_SIZE);
  }
  std::chrono::time_point<std::chrono::high_resolution_clock> start = std::chrono::high_resolution_clock::now();
#ifdef VERBOSE
  cout<<"key hex:"<< stoh(string((const char*)key_hash))<<endl;
  cout<<"nonce hex:"<< stoh(text_nonce)<<endl;
#endif
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t*)key_hash);
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
 * File to file nonce generated by itself.
 * */
void cmd_enc(string infile_name, string oufile_name, c20::config configs){
  Bytes cur;
  cc20_dev::init_byte_rand_cc20(cur,NONCE_SIZE);
  string text_nonce = cc20_dev::btos(cur);
  uint8_t key_hash[65]= {0};
  uint8_t inonce [NONCE_SIZE] = {0};
  Cc20 cry_obj (configs.core_count);
#ifndef WEB_RELEASE
  if (!cry_obj.check_file(infile_name))
    return;
#endif// WEB_RELEASE
  cry_obj.set_configurations(configs);
  string text_key;
  cout << "Password:" << endl;
  std::getline(std::cin, text_key);
  cry_obj.get_key_hash(text_key, key_hash);
  string infile_name_copy=infile_name+".pdm";
  if(cry_obj.is_dec()){
    text_nonce = cry_obj.get_inp_nonce(infile_name_copy, inonce);
    text_nonce = text_nonce.substr(0,24);//pad_to_key((string) text_nonce.substr(0,24), NONCE_SIZE);
  }
  std::chrono::time_point<std::chrono::high_resolution_clock> start = std::chrono::high_resolution_clock::now();
#ifdef VERBOSE
  cout<<"key hex:"<< stoh(string((const char*)key_hash))<<endl;
  cout<<"nonce hex:"<< stoh(text_nonce)<<endl;
#endif
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t*)key_hash);
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
  key_hash.add(cc20_dev::stob(text_key).data(),text_key.size());
  key_hash.add(cc20_dev::stob(text_key).data(),text_key.size());
  string infile_name_copy;
  if(cry_obj.conf.DE){
    uint8_t *line1[NONCE_SIZE]={0};
    infile_name_copy = infile_name+".pdm";
    FILE * infile = fopen(infile_name_copy.data(), "rb");
    fread(line1,sizeof(char), NONCE_SIZE,infile);
    if(line1!=NULL)
      text_nonce=(char*)line1;
    fclose(infile);
  }
  else {
    cc20_dev::init_byte_rand_cc20(nonce,NONCE_SIZE);
    text_nonce = cc20_dev::btos(nonce);
  }
  if (text_nonce.size() != 0) {
    text_nonce = cc20_dev::pad_to_key((string) text_nonce, NONCE_SIZE);
  }

//  cry_obj.set_vals((uint8_t*)text_nonce.data(), (uint8_t *)key_hash.getHash().data());
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t *)key_hash.getHash().data());
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
  key_hash.add(cc20_dev::stob(text_key).data(),text_key.size());
  key_hash.add(cc20_dev::stob(text_key).data(),text_key.size());
  string infile_name_copy;
  uint8_t line1[NONCE_SIZE]={0};
  if(cry_obj.conf.DE){
    for (unsigned int i=0;i<NONCE_SIZE;i++)
      line1[i]=(buf[i]);
    text_nonce=(char*)line1;
  }
  else {
    cc20_dev::init_byte_rand_cc20(nonce,NONCE_SIZE);
    text_nonce = cc20_dev::btos(nonce);
  }
  if (text_nonce.size() != 0) {
    text_nonce = cc20_dev::pad_to_key((string) text_nonce, NONCE_SIZE);
  }

  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t *)key_hash.getHash().data());
//  cry_obj.set_vals((uint8_t*)text_nonce.data(), (uint8_t *)key_hash.getHash().data());
  cry_obj.poly->init((unsigned char *)key_hash.getHash().data());
  if(cry_obj.conf.DE){
    cry_obj.rd_file_encr(buf,oufile_name, outsize );
  }
  else {
    cry_obj.rd_file_encr(buf,oufile_name, outsize);
  }
}


/**
 * For web, memory to memory encryption.
 * Takes plain, outputs hex string
 * Note: for mobile please hash the key in client code,
 *          and use ck_enc(...).
 * */
// EMSCRIPTEN_KEEPALIVE
void cmd_enc(uint8_t* buf, size_t input_length, uint8_t* outstr , string text_key){
  // cout<<"[cc20_multi] encryption start."<<endl;
  Bytes cur;
  cc20_dev::init_byte_rand_cc20(cur,NONCE_SIZE);
  string text_nonce = cc20_dev::btos(cur);
  Cc20  cry_obj;
  cry_obj.conf.DE=0;
  cry_obj.conf.DISPLAY_PROG=0;
  uint8_t key_hash[65]= {0};
  cry_obj.get_key_hash(std::move(text_key), key_hash);
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t*)key_hash);
  cry_obj.poly->init((unsigned char *)key_hash);
  cry_obj.rd_file_encr(buf, outstr, input_length);
}

/**
 * For web, memory to memory decryption.
 * Takes hex string, outputs plain.
 * Note: for mobile please hash the key in client code,
 *          and use ck_dec(...).
 * */
// EMSCRIPTEN_KEEPALIVE 
void cmd_dec(uint8_t* buf, size_t input_length, uint8_t* outstr , string text_key){
  Cc20  cry_obj;
  cry_obj.conf.DE=1;
  cry_obj.conf.DISPLAY_PROG=0;
  uint8_t key_hash[65]= {0};
  cry_obj.get_key_hash(std::move(text_key), key_hash);
  cry_obj.poly->init((unsigned char *)key_hash);
  Bytes input_vc;
  for(size_t i=0 ; i<NONCE_SIZE;i++)
    input_vc.push_back(buf[i]);
  string text_nonce = cc20_dev::btos(input_vc);
  if (!text_nonce.empty()) {
    text_nonce = cc20_dev::pad_to_key((string) text_nonce, NONCE_SIZE);
  }
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t*)key_hash);
  cry_obj.rd_file_encr(buf, outstr, input_length);
}
/**
 * For client.
 * Used in desktop
 * */
void PDM_BRIDGE_MOBILE::cmd_enc(const  uint8_t* buf, size_t input_length, uint8_t* outstr , const  uint8_t* _key){
  Bytes cur;
  cc20_dev::init_byte_rand_cc20(cur,NONCE_SIZE);
  string text_nonce = cc20_dev::btos(cur);
  Cc20  cry_obj;
  cry_obj.conf.DE=0;
  cry_obj.conf.DISPLAY_PROG=0;
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), _key);
  cry_obj.poly->init((unsigned char *)_key);
  cry_obj.rd_file_encr(buf, outstr, input_length);
}

/**
 * For client.
 * Used in desktop
 * */
void PDM_BRIDGE_MOBILE::cmd_dec(const  uint8_t* buf, size_t input_length, uint8_t* outstr , const  uint8_t* _key){
  Cc20  cry_obj;
  cry_obj.conf.DE=1;
  cry_obj.conf.DISPLAY_PROG=0;
  cry_obj.poly->init((unsigned char *)_key);
  Bytes input_vc;
  for(size_t i=0 ; i<NONCE_SIZE;i++)
    input_vc.push_back(buf[i]);
  string text_nonce = cc20_dev::btos(input_vc);
  if (!text_nonce.empty()) {
    text_nonce = cc20_dev::pad_to_key((string) text_nonce, NONCE_SIZE);
  }
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t*)_key);
  cry_obj.rd_file_encr(buf, outstr, input_length);
}
/**
 * For mobile, memory to memory encryption.
 * Doesn't calculate scrypt.
 * Takes plain, outputs hex string
 * */
// EMSCRIPTEN_KEEPALIVE
void PDM_BRIDGE_MOBILE::ck_enc(uint8_t* buf, size_t input_length, uint8_t* outstr , const string& text_key){
  // cout<<"[cc20_multi] encryption start."<<endl;
  Bytes cur;
  cc20_dev::init_byte_rand_cc20(cur,NONCE_SIZE);
  string text_nonce = cc20_dev::btos(cur);
  Cc20  cry_obj;
  cry_obj.conf.DE=0;
  cry_obj.conf.DISPLAY_PROG=0;
//  uint8_t key_hash[65]= {0};
//  cry_obj.get_key_hash(text_key, key_hash);
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t*)text_key.data());
  cry_obj.poly->init((unsigned char *)text_key.data());
  cry_obj.rd_file_encr(buf, outstr, input_length);
}

/**
 * For mobile, memory to memory decryption.
 * Doesn't calculate scrypt.
 * Takes hex string, outputs plain
 * */
// EMSCRIPTEN_KEEPALIVE
void PDM_BRIDGE_MOBILE::ck_dec(uint8_t* buf, size_t input_length, uint8_t* outstr , const string& text_key){
  Cc20  cry_obj;
  cry_obj.conf.DE=1;
  cry_obj.conf.DISPLAY_PROG=0;
//  uint8_t key_hash[65]= {0};
//  cry_obj.get_key_hash(std::move(text_key), key_hash);
  cry_obj.poly->init((unsigned char *)text_key.data());
  Bytes input_vc;
  for(size_t i=0 ; i<NONCE_SIZE;i++)
    input_vc.push_back(buf[i]);
  string text_nonce = cc20_dev::btos(input_vc);
  if (!text_nonce.empty()) {
    text_nonce = cc20_dev::pad_to_key((string) text_nonce, NONCE_SIZE);
  }
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t*)text_key.data());
  cry_obj.rd_file_encr(buf, outstr, input_length);
}

void PDM_BRIDGE_MOBILE::ck_crypt(uint8_t* buf,
                                 size_t input_length,
                                 uint8_t*outstr,
                                 uint8_t*nonce,
                                 const uint8_t*key,
                                 size_t offset
){
  Cc20  cry_obj;
  cry_obj.conf.poly1305_toggle = 0;
  cry_obj.conf.DISPLAY_PROG=0;
  cry_obj.conf.pure_xor = 1;
  cry_obj.conf.DE = 0;
  cry_obj.x_set_vals(nonce, key);
  cry_obj.rd_file_encr(buf, outstr, input_length);
}

void PDM_MEM_SIDE_CHANNEL::crypt_x_times(uint8_t* buf,
                                 size_t input_length,
                                 uint8_t*outstr,
                                 uint8_t*nonce,
                                 const uint8_t*key,
                                 size_t offset,
                                 size_t x
){
  Cc20  cry_obj;
  cry_obj.conf.poly1305_toggle = 0;
  cry_obj.conf.DISPLAY_PROG=0;
  cry_obj.conf.pure_xor = 1;
  cry_obj.conf.DE = 0;
  cry_obj.x_set_vals(nonce, key);
  for (int i=0;i<x;i++){
#ifdef VERBOSE
    cout<<"[crypt_x_times] in loop = "<<i<<". " << endl;
#endif
    cry_obj.rd_file_encr(buf, outstr, input_length);
  }
}


void cmd_enc_s(const uint8_t* buf, size_t input_length,
             uint8_t* outstr , const uint8_t* _key, size_t _key_size){
  Bytes cur;
  cc20_dev::init_byte_rand_cc20(cur,NONCE_SIZE);
  string text_nonce = cc20_dev::btos(cur);
  Cc20  cry_obj;
  cry_obj.conf.DE=0;
  cry_obj.conf.DISPLAY_PROG=0;

  uint8_t key_hash[65]= {0};
  string text_key((const char*)_key,_key_size);
  cry_obj.get_key_hash(text_key, key_hash);
  text_key.erase(0,_key_size);

  helper_print_stats((uint8_t*)key_hash,32);
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t*)key_hash);
  cry_obj.poly->init((unsigned char *)key_hash);
  cry_obj.rd_file_encr(buf, outstr, input_length);
  text_nonce.erase(0,text_nonce.size());
}
void cmd_dec_s(const uint8_t* buf, size_t input_length,
             uint8_t* outstr , const uint8_t* _key, size_t _key_size){
  Cc20  cry_obj;
  cry_obj.conf.DE=1;
  cry_obj.conf.DISPLAY_PROG=0;
  uint8_t key_hash[65]= {0};

  string text_key((const char*)_key,_key_size);
  cry_obj.get_key_hash(text_key, key_hash);
  text_key.erase(0,_key_size);
  cry_obj.poly->init((unsigned char *)key_hash);
  Bytes input_vc;
  for(size_t i=0 ; i<NONCE_SIZE;i++){
    input_vc.push_back(buf[i]);
  }
  string text_nonce = cc20_dev::btos(input_vc);

  if (!text_nonce.empty()) {
    text_nonce = cc20_dev::pad_to_key((string) text_nonce, NONCE_SIZE);
  }
  cry_obj.x_set_vals((uint8_t*)text_nonce.data(), (uint8_t*)key_hash);
  cry_obj.rd_file_encr(buf, outstr, input_length);
  text_nonce.erase(0,text_nonce.size());
}

void Cc20::end_cleanup() {
  crypto_rand crand;
  // cy[][] cleanup
  for (auto&i:cy){
    for (auto&f:i) {
      f = crand.nextInt();
    }
  }
  crand.reset();
  // folow[][] cleanup
  for (auto&i:folow){
    for (auto&f:i) {
      f = crand.nextInt();
    }
  }
  // nonce cleanup
  crand.reset();
  for (auto i=0;i<NONCE_SIZE;i++){
    nonce_orig[i] = crand.nextByte();
  }
  // buffer cleanup
  crand.reset();
  for (auto & i : nex){
    for (auto f=0;f<64;f++) {
      i[f] = crand.nextByte();
    }
  }

}


