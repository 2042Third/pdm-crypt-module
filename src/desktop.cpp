//
// Created by Yi Yang on 6/26/2022.
//
#include "types.h"

//#include "xCc20.h"
#include "cc20_multi.h"

// KDF test
#include "cc20_scrypt.h"

#ifndef PDM_CC20_DEV_HPP
#include "cc20_dev.hpp"
#endif // PDM_CC20_DEV_HPP
using namespace std;

//#ifdef HAS_MAIN
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
int main(int argc, char ** argv) {
  string infile,oufile,nonce;
  c20::config configs = rd_inp(argc,argv,&infile);
  if (configs.arg_c!=2){
    cout<<"Must have 1 file input, -h for help."<<endl;
    return 0;
  }
  Bytes cur ;
  init_byte_rand_cc20(cur,NONCE_SIZE); // xchacha20
  nonce="1";
  cmd_enc(infile,"",btos(cur), configs);
  return 0;
}
//#endif // HAS_MAIN