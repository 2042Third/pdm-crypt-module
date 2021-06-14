/*
cc20_multi.cpp

pdm/Personal Data Management system is a encrypted and multiplatform data searching, building, archiving tool.
This is the encryption core module for pdm.

author:     Yi Yang
            5/2021
*/

//cc20_multi.cpp    

// #ifndef BOOST_STRING_TRIM_HPP
// #define BOOST_STRING_TRIM_HPP

#include "cc20_multi.h"
#include "../lib/sha3.h"
// #include <condition_variable>
#include <boost/algorithm/string/trim.hpp>
#include <boost/thread/thread.hpp>


using namespace std;
using boost::thread;



// string hashing = "00000000000000000000000000000000"; // A rolling hash of the the input data.

const int BLOCK_SIZE = 9216000;
/* Invariant: BLOCK_SIZE % 64 == 0
                                 115200, 256000, 576000, 1152000,2304000,4608000,6912000,9216000 ...
                                 Block size*/

const int THREAD_COUNT = 30; // Make sure to change the header file's too.

const int PER_THREAD_BACK_LOG = 0; // This is not enabled.

uint32_t folow[THREAD_COUNT][17]; // A copy of a state.

// Statically allocates, and uses BLOCK_SIZE*THREAD_COUNT of memory. 
char thread_track[THREAD_COUNT][BLOCK_SIZE] = {{0}};

long int writing_track[THREAD_COUNT]; // Tells the writer thread how much to read; should only be different on the last block.

char *linew;

long int arg_track[THREAD_COUNT][6];
/* Passes arguments into threads.
                                       arg_track[THREAD_COUNT][0] ---> Thread number
                                       arg_track[THREAD_COUNT][1] ---> NOT USED
                                       arg_track[THREAD_COUNT][2] ---> NOT USED
                                       arg_track[THREAD_COUNT][3] ---> Remaining plain size
                                       arg_track[THREAD_COUNT][4] ---> NOT USED*/

// SHA3 hashing; // A rolling hash of the input data.

uint8_t * arg_line[THREAD_COUNT]; // Addresses of memory mapped plain text from disk.

uint32_t arg_count[THREAD_COUNT]; // Count of each chacha 20 block

Cc20 * arg_ptr[THREAD_COUNT]; // Parent pointers for each thread.

// recursive_mutex locks[THREAD_COUNT]; // All locks for threads, each waits for the writing is done on file or memory.

boost::thread threads[THREAD_COUNT]; // Threads

char ** outthreads;

int final_line_written = 0; // Whether or not the fianl line is written

// mutex mtx;

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
  endicha(this -> nex[thrd], folow[thrd]);
}

/*
    Creates one thread for writing and THREAD_COUNT threads for calculating the 
    cypher text. It also handles disk mapping for reading, and opens oufile for 
    writing. After, it will dispatch threads when there are vacancy in threads[].
    Returns when all plain is read, and all threads are joined.

*/

void Cc20::rd_file_encr(const std::string file_name, string oufile_name) {
  std::vector < uint8_t > content;
  unsigned long int n = 0;

  struct stat sb;
  long int fd, fdw;
  uint8_t * data;
  uint8_t * dataw;
  uint8_t * line; 
  fd = open(file_name.data(), O_RDONLY); // Reading file
  if (fd == -1) {
    perror("Cannot open file ");
    cout << file_name << " ";
    exit(1);
  }
  fdw = open(oufile_name.data(), O_RDWR|O_CREAT|O_TRUNC|O_NONBLOCK
              ,S_IRWXU); // Writing file
  if (fdw == -1) {
    perror("Cannot open file ");
    cout << oufile_name << " ";
    exit(1);
  }

  fstat(fd, & sb);

  #ifdef VERBOSE
  cout << "Staring file size " << sb.st_size << endl;
  #endif
  linew = new char[sb.st_size];
  data = (uint8_t * )(mmap( 0, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
  // dataw = (uint8_t * )(mmap( 0, sb.st_size, PROT_WRITE, MAP_SHARED, fdw, 0));
  line = data;
  // linew = dataw;
  long int tn = 0;
  n = sb.st_size;

  uint32_t count = 0;
  for (long int i = 0; i < THREAD_COUNT; i++) {
    writing_track[i] = 0;
  }
  long int tracker = 0;
  long int np = 0, tmpn = np % THREAD_COUNT;
  // thread rthread;
  // // cout << "Reaching out" << endl;
  // if (oufile_name == "a") {
  //   cout << "MEM creating: " << sb.st_size / BLOCK_SIZE + 2 << endl;
  //   // uint8_t tmpthread[sb.st_size/BLOCK_SIZE+1][BLOCK_SIZE] = {{0}};
  //   outthreads = (char ** ) new uint8_t * [sb.st_size / BLOCK_SIZE + 1];
  //   for (unsigned int i = 0; i < sb.st_size / BLOCK_SIZE + 1; i++) {
  //     outthreads[i] = (char * ) new uint8_t[BLOCK_SIZE];
  //   }
  //   // cout<<"MEM created: "<< outthreads[0][0]<<endl; 
  //   set_thread_arg(np % THREAD_COUNT, np, tracker, n, 0, line, count, this);
  //   rthread = thread(enc_writing_nw);
  // } else {

  //   // rthread = std::thread(enc_writing, oufile_name);

  // }
  set_thread_arg(np % THREAD_COUNT, (long int)linew, tracker, n, 0, line, count, this);
  threads[np % THREAD_COUNT] = thread(multi_enc_pthrd, tmpn);
  np++;
  
  for (unsigned long int k = 0; k < ((unsigned long int)(sb.st_size / 64) + 1); k++) { // If leak, try add -1

    if (n >= 64) {
      tracker += 64;
      if (tn % (BLOCK_SIZE) == 0 && (k != 0)) {
        if (threads[np % THREAD_COUNT].joinable()) {
          #ifdef VERBOSE
          cout << "[main] Possible join, waiting " <<np % THREAD_COUNT<< endl;
          #endif
          threads[np % THREAD_COUNT].join();
        }
        set_thread_arg(np % THREAD_COUNT, (long int)linew+tn, tracker, n, tn, line + tn, count + 1, this);
        threads[np % THREAD_COUNT] = thread(multi_enc_pthrd, np % THREAD_COUNT);

        tracker = 0;
        np++;
      }
    } else {
      // cout << "Uneven data reached, offset " << n << endl;
      if (threads[np % THREAD_COUNT].joinable() && final_line_written != 1) {
          #ifdef VERBOSE
          cout << "[main] Last Possible join, waiting " <<np % THREAD_COUNT<< endl;
          #endif
        threads[np % THREAD_COUNT].join();
      }
      set_thread_arg(np % THREAD_COUNT, (long int)linew+tn, tracker, n, tn, line + tn, count + 1, this);
      threads[np % THREAD_COUNT] = thread(multi_enc_pthrd, np % THREAD_COUNT);
    }
    count += 1;
    n -= 64;
    tn += 64;
  }
  #ifdef VERBOSE
  cout << "[main] Finished dispatching joining" << endl;
  #endif
  #ifndef DE
  // hashing.add(line,sb.st_size );
  // cout<<"SHA3 of the input file: "<< hashing.getHash()<<endl;
  // #else 
  // hashing.add(linew,sb.st_size );
  #endif // DE
  for (int i = 0; i < THREAD_COUNT; i++) {
    // cout<<"Trying"<<endl;
    if (threads[i].joinable()){

      // cout << "[main] thread joining "<< i << endl;
      threads[i].join();

    }
  }

  // #ifdef VERBOSE
  // cout << "[main] All calc threads joined" << endl;
  // #endif
  // if (oufile_name.size() != 0)
  // {
  //   rthread.join();
    
  //   // cout << "[main] Writing thread joined" << endl;
  // }
  FILE * oufile;
  oufile = fopen(oufile_name.data(), "wb");
  fclose(oufile);
  oufile = fopen(oufile_name.data(), "ab");
  fwrite(linew, sizeof(char), sb.st_size, oufile);
  fclose(oufile);

  #ifdef VERBOSE
  cout << "[main] Writing thread joined" << endl;
  #endif
  // cout << "Cleaning mem" << endl;
  if (oufile_name == "a") {
    for (unsigned int i = 0; i < sb.st_size / BLOCK_SIZE + 1; i++) {
      delete[] outthreads[i];
    }
    delete[] outthreads;
  }
  delete[] linew;
  if (munmap(data,sb.st_size)!=0)
    fprintf(stderr,"Cannot close");
  close(fd);

  if (munmap(dataw,sb.st_size)!=0)
    fprintf(stderr,"Cannot close");
  close(fdw);
  // cout << "finished" << endl;
}

/*
    Sets arguments in arg_track for threads.

*/

void set_thread_arg(int thrd, long int linew, long int tracker, long int n, long int tn, uint8_t * line, uint32_t count, Cc20 * ptr) {
  arg_track[thrd][0] = thrd;
  arg_track[thrd][1] = linew; 
  arg_track[thrd][2] = tracker; 
  arg_track[thrd][3] = n;

  arg_line[thrd] = line;
  arg_count[thrd] = count;
  arg_ptr[thrd] = ptr;
}

void multi_enc_pthrd(int thrd) {
  uint8_t * linew = (uint8_t*)arg_track[thrd][1]; // Set but not used
  long int tracker = 0; // Used
  long int n = arg_track[thrd][3]; // Used 
  uint8_t * line = arg_line[thrd]; // Used
  uint32_t count = arg_count[thrd]; // Used 
  Cc20 * ptr = arg_ptr[thrd];

  #ifdef VERBOSE
          cout<<"[calc] "<<thrd<<" locks, starting write " << endl;
  #endif
  // if (thrd==0){
  //   cout<<"Trying to lock"<<endl;
  // }
  // locks[thrd].lock();
  // if (thrd==0){
  //   cout<<"locked"<<endl;
  // }
  for (unsigned long int k = 0; k < BLOCK_SIZE / 64; k++) {
    ptr -> one_block((int) thrd, (int) count);

    if (n >= 64) {
      for (long int i = 0; i < 64; i++) {
        // thread_track[thrd][tracker + i] = (char)(line[i + tracker] ^ ptr -> nex[thrd][i]);
        linew[i + tracker] = (char)(line[i + tracker] ^ ptr -> nex[thrd][i]);
      }

      tracker += 64;
      if (tracker >= (BLOCK_SIZE)) { // Notifies the writing tread when data can be read
        if (msync(linew, tracker, MS_SYNC) == -1)
        {
            // #ifdef VERBOSE
            //   cout<<"[calc] "<<thrd<<" Error found " << endl;
            // #endif
            // perror("Could not sync the file to disk");
        }
        writing_track[thrd] = tracker;
        // hashing.add(line,tracker);
        // cout<< "SHA3 new state: " << hashing.getHash()<<endl;
        tracker = 0;
        // np++;
        #ifdef VERBOSE
          cout<<"[calc] "<<thrd<<" returning lock, calling write, size "<<writing_track[thrd] << endl;
        #endif
      }
      // locks[np].unlock();
      // mtx.unlock();
    } else {
      for (int i = 0; i < n; i++) {
        // thread_track[thrd][tracker + i] = (char)(line[i + tracker] ^ ptr -> nex[thrd][i]);
        linew[i+tracker] = (char)(line[i + tracker] ^ ptr -> nex[thrd][i]);
      }
      tracker += n;
      writing_track[thrd] = tracker; // Notifies the writing tread when data can be read
      if (msync(linew, tracker, MS_SYNC) == -1)
      {
          //   #ifdef VERBOSE
          //     cout<<"[calc] "<<thrd<<" Error found " << endl;
          //   #endif
          // perror("Could not sync the file to disk");
      }
        #ifdef VERBOSE
        cout<<"[calc] "<<thrd<<" on last lock, size "<<writing_track[thrd]<< endl;
        #endif
      // hashing.add(line,tracker);
      //   cout<< "SHA3 new state: " << hashing.getHash()<<endl;
      // locks[np].unlock();
      // return ;
      break;
    }
    count += 1;
    n -= 64;
  }
  #ifdef VERBOSE
          cout<<"[calc] "<<thrd<<" unlocks " << endl;
  #endif
  // locks[thrd].unlock();
}


void enc_writing(string oufile_name) {
  FILE * oufile;
  oufile = fopen(oufile_name.data(), "wb");
  fclose(oufile);
  oufile = fopen(oufile_name.data(), "ab");
  long int local_np = 0;
  int mutex_num;
  while (final_line_written != 1) {
    mutex_num = local_np % THREAD_COUNT;
    // locks[mutex_num].lock();
    if (local_np % THREAD_COUNT==0){
      cout<<"Write trying to lock"<<endl;
    }
    if (writing_track[local_np % THREAD_COUNT] != 0) {

      if (writing_track[local_np % THREAD_COUNT] >= BLOCK_SIZE) {
        // mtx.lock();
        #ifdef VERBOSE
        cout << "[writ] "<<local_np% THREAD_COUNT << " Writing started " << writing_track[local_np % THREAD_COUNT] << endl;
        #endif
        fwrite(thread_track[local_np % THREAD_COUNT], sizeof(char), writing_track[local_np % THREAD_COUNT], oufile);
        #ifdef DE
        // hashing.add(thread_track[local_np % THREAD_COUNT],writing_track[local_np % THREAD_COUNT]);
        #endif //DE
        writing_track[local_np % THREAD_COUNT] = 0;
        // mtx.unlock();
        local_np++;
      } else {
        // mtx.lock();

        #ifdef VERBOSE
        cout <<"[writ] "<< local_np% THREAD_COUNT << " Writing ended " << writing_track[local_np % THREAD_COUNT] << endl;
        #endif
        fwrite(thread_track[local_np % THREAD_COUNT], sizeof(char), writing_track[local_np % THREAD_COUNT], oufile);
        #ifdef DE
        // hashing.add(thread_track[local_np % THREAD_COUNT],writing_track[local_np % THREAD_COUNT]);
        #endif // DE
        final_line_written = 1;
        fflush(oufile);
        // break;
        // mtx.unlock();
      }
    }
    if (local_np % THREAD_COUNT==0){
      cout<<"unlock"<<endl;
    }
    // locks[mutex_num].unlock();
  }
  fclose(oufile);
  #ifdef VERBOSE
  cout << "[writ] Writing thread closed" << endl;
  #endif
}

void enc_writing_nw() {

  long int local_np = 0;
  while (final_line_written != 1) {
    if (writing_track[local_np % THREAD_COUNT] != 0) {

      if (writing_track[local_np % THREAD_COUNT] >= BLOCK_SIZE) {
        // mtx.lock();

        #ifdef VERBOSE
        cout << local_np << " Writing started " << writing_track[local_np % THREAD_COUNT] << endl;
        #endif
        memcpy(outthreads[local_np], thread_track[local_np % THREAD_COUNT], sizeof(thread_track[local_np % THREAD_COUNT]));
        writing_track[local_np % THREAD_COUNT] = 0;
        
        local_np++;
      } else {
        #ifdef VERBOSE
        cout << local_np << " Writing ended " << writing_track[local_np % THREAD_COUNT] << endl;
        #endif
        memcpy(outthreads[local_np], thread_track[local_np % THREAD_COUNT], sizeof(thread_track[local_np % THREAD_COUNT]));
        final_line_written = 1;
      }
    }
  }
  // cout << "Writing thread closed" << endl;
}

void Cc20::set_vals(uint8_t * nonce, uint8_t * key) {
  this -> nonce = nonce;
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
    expan(this -> cy[i], 4, key, 8);
  }
}

void Cc20::endicha(uint8_t * a, uint32_t * b) {
  for (unsigned int i = 0; i < 16; i++) {
    U32T8_S(a + 4 * i, b[i]);

  }
}

int new_way(string usr_input) {

  //Encryption
  Cc20 test;
  std::string infile_name, oufile_name, text_key;
  Bytes key;
  Bytes nonce;

  oufile_name = "encrypted.pdm";

  #ifdef DE
  cout << "输入加密文件名： " << endl;
  #else
  cout << "输入文件名进行加密： " << endl;
  #endif
  std::getline(std::cin, infile_name);
  cout<<infile_name<<endl;
  boost::algorithm::trim(infile_name);
  cout<<infile_name<<endl;


  #ifdef LINUX
  termios oldt;
  tcgetattr(STDIN_FILENO, & oldt);
  termios newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, & newt);
  cout << "输入密码： " << endl;
  std::getline(std::cin, text_key);
  tcsetattr(STDIN_FILENO, TCSANOW, & oldt);
  cout << endl;
  #endif

  #ifdef WINDOWS
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  GetConsoleMode(hStdin, & mode);
  SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
  cout << "输入密码： " << endl;
  std::getline(std::cin, text_key);
  #endif

  string tmp;
  cout << "输入独立数字：" << endl;
  getline(cin, tmp);

  if (tmp.size() != 0) {
    tmp = pad_to_key((string) tmp, 13);
    nonce = stob(tmp);
  }
  SHA3 key_hash;
  key_hash.add(stob(text_key).data(),text_key.size());
  // printf("plai of the key %s\n",text_key.data());
  // printf("hash of the key %s\n", key_hash.getHash().data());
  // text_key = pad_to_key(text_key, 32);


  auto start = std::chrono::high_resolution_clock::now();

  test.set_vals(nonce.data(), (uint8_t *)key_hash.getHash().data());
  cout << "Read/Write encryption from file: " << infile_name << endl;

  #ifdef DE
  test.rd_file_encr(infile_name + ".pdm", "dec-" + infile_name);
  
  // cout <<"SHA3 of the entire file: "<<hashing.getHash()<<endl;
  cout << "已解密: " << "dec-" + infile_name << endl;

  #else
  test.rd_file_encr(infile_name, infile_name+".pdm");
  
  // cout <<"SHA3 of the entire file: "<<hashing.getHash()<<endl;
  // test.rd_file_encr(infile_name, infile_name + ".pdm");
  cout << "完成加密: " << infile_name + ".pdm" << endl;
  #endif

  auto end = std::chrono::high_resolution_clock::now();

  auto dur = end - start;
  auto i_millis = std::chrono::duration_cast < std::chrono::milliseconds > (dur);
  auto f_secs = std::chrono::duration_cast < std::chrono::duration < float >> (dur);
  std::cout << f_secs.count() << '\n';
  start = std::chrono::high_resolution_clock::now();

  // #endif

  return 0;
}

int main(int argc, char ** argv) {
  if (argc != 2) {
    string usr_input = "";
    cout << "new method: \n" << new_way(usr_input) << "\n\n";
  } else {
    string usr_input(argv[1], (int) sizeof(argv[1]) / sizeof(char));
    cout << "new method: \n" << new_way(usr_input) << "\n\n";
  }
  return 0;
}
