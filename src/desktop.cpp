//
// Created by Yi Yang on 6/26/2022.
//
#include "types.h"
#include "cc20_multi.h"
#include "empp.h"
// KDF test
#include <cstring>
using namespace std;
namespace web_test{
//  /**
//   * Basic encryption and decryption demo
//   * @param a key for encryption
//   * @param b message to be encrypted
//   * @param accum for r_test() only, default -1
//   * */
//  int test ( const std::string& a, const std::string& b, int accum){
//    std::string pas = "12345";
//    std::string a_copy=a,b_copy=b;
//    const std::string enc = loader_check(a_copy, b_copy);
//    const std::string dec = loader_out(a_copy, enc);
//    std::string decWrong = loader_out(pas, enc);
//    int ttl = 1000000;
//    if(accum==-1){
//      std::cout<<"Input key: \t"<<a<<std::endl;
//      std::cout<<"Input message: \t"<<b<<std::endl;
//      std::cout<<"Encrypted message: \t"<<enc<<std::endl;
//      std::cout<<"Decrypted message: \t"<<dec<<std::endl;
//      std::cout<<"\"12345\" Decrypted message: \t"<<decWrong<<std::endl;
//      return 1;
//    }
//    if (dec == b){
//      accum+=1;
//      std::cout<<accum/10000<< "% pass\r";
//    }
//    else {
//      std::cout<<"failure!!"<<std::endl;
//      std::cout<< "\tgot     : "<<dec<<std::endl;
//      std::cout<< "\texpected: "<<b<<std::endl;
//    }
//    return accum;
//  }
  int test_scrypt (const std::string& a, const std::string& b, int accum=-1){
    std::string c = scrypt(a);
    std::string enc = checker_in(c, b);
    std::string dec = checker_out(c, enc);
    std::string pas2 = "12345";
    std::string decWrong = loader_out(pas2, enc);
    int ttl = 1000000;
    if(accum==-1){
      std::cout<<"Input key: \t"<<a<<std::endl;
      std::cout<<"Scrypt key: \t"<<c<<std::endl;
      std::cout<<"Input message: \t"<<b<<std::endl;
      std::cout<<"Encrypted message: \t"<<enc<<std::endl;
      std::cout<<"Decrypted message: \t"<<dec<<std::endl;
      std::cout<<"\"12345\" Decrypted message: \t"<<decWrong<<std::endl;
      return 1;
    }
    if (dec == b){
      accum+=1;
      std::cout<<accum/10000<< "% pass\r";
    }
    else {
      std::cout<<"failure!!"<<std::endl;
      std::cout<< "\tgot     : "<<dec<<std::endl;
      std::cout<< "\texpected: "<<b<<std::endl;
    }
    return accum;
  }
  int test_enc_dec (const std::string& a, const std::string& b, int accum=-1){
    std::string c = scrypt(a);
    std::string b_copy = b;
    std::string enc = loader_check(c, b_copy);
    std::string dec = loader_out(c, enc);
    std::string pas2 = "12345";
    std::string decWrong = loader_out(pas2, enc);
    int ttl = 1000000;
    if(accum==-1){
      std::cout<<"Input key: \t"<<a<<std::endl;
      std::cout<<"Scrypt key: \t"<<c<<std::endl;
      std::cout<<"Input message: \t"<<b<<std::endl;
      std::cout<<"Encrypted message: \t"<<enc<<std::endl;
      std::cout<<"Decrypted message: \t"<<dec<<std::endl;
      std::cout<<"\"12345\" Decrypted message: \t"<<decWrong<<std::endl;
      return 1;
    }
    if (dec == b){
      accum+=1;
      std::cout<<accum/10000<< "% pass\r";
    }
    else {
      std::cout<<"failure!!"<<std::endl;
      std::cout<< "\tgot     : "<<dec<<std::endl;
      std::cout<< "\texpected: "<<b<<std::endl;
    }
    return accum;
  }
  /**
   * Runs the encryption and decryption for 1,000,000 times
   * and count the accuracy.
   * *Not useful after the initial implementation.
   * */
  int r_test(int count){
    std::string pas = "1234";
    std::string tmp2 = "hello this is a message";
    int accum =0;
    for (unsigned int i=0 ; i< count;i++){
//      accum = test(pas, tmp2, accum);
    }
    std::cout<<std::endl;
    return 1;
  }
  /**
   * Basic public key DH test
   * */
  int curve_test (){
    size_t testsize=0;
    uint8_t test[C20_ECC_SIZE];
    std::string ttmp="3a57718b1da04cc0c52f626212e5c82a";
    for(auto i:ttmp){
      test[testsize]=i;
      testsize++;
    }
    std::string tmpshr="";
    for(int i=0;i<C20_ECC_SIZE;i++)
      tmpshr.append(1,(char)test[i]);
    // std::cout<<test<<std::endl;
    // std::cout<<stoh(tmpshr)<<std::endl;

    // Alice
    std::string seca = gen_sec();
    std::string puba = gen_pub(seca);

    // Bob
    std::string secb = gen_sec();
    std::string pubb = gen_pub(secb);

    //agreenent
    std::string shra = gen_shr(seca,pubb);
    std::string shrb = gen_shr(secb,puba);
    printf("Alice secret and public: \"%s\", \"%s\"\n",seca.data(),puba.data());
    printf("Bob   secret and public: \"%s\", \"%s\"\n",secb.data(),pubb.data());
    printf("Alice shared: \"%s\"\n",shra.data());
    printf("Bob   shared: \"%s\"\n",shrb.data());
    return 1;
  }

  void print_stats(const uint8_t* a,size_t size,int binary=1){
    string ac ((const char*)a,0,size);
    if(!binary)cout<< "Plain: "<<ac<<endl;
    cout<< " Hax : "<<stoh(ac)<<endl;
    cout<< "Hash : "<<get_hash(ac)<<endl;
  }

  int pure_crypt_test(){
    size_t iosize = cc20_utility::nonce_key_pair_size();
    std::string input_buffer,output_buffer, key_buffer;
    input_buffer.reserve(cc20_utility::nonce_key_pair_size()+1);
    output_buffer.reserve(cc20_utility::nonce_key_pair_size()+1);
    key_buffer.reserve(cc20_utility::nonce_key_pair_size()+1); key_buffer.clear();

    for (auto i=0;i<cc20_utility::nonce_key_pair_size();i++){
      input_buffer.data()[i] = '-';
      output_buffer.data()[i] = '-';
      key_buffer.data()[i] = 0;
    }
    cc20_utility::gen_key_nonce_pair((unsigned char*)key_buffer.data(),cc20_utility::nonce_key_pair_size());
    printf("Randomly generated nonce & key pair \n");
    print_stats((unsigned char*)key_buffer.data(),cc20_utility::nonce_key_pair_size());
    uint8_t nonce [NONCE_SIZE+1],key[CC20_KEY_SIZE+1];
    memcpy(nonce,key_buffer.data(),NONCE_SIZE);
    memcpy(key,key_buffer.data()+NONCE_SIZE,CC20_KEY_SIZE);
    cout<<"Split nonce: "<<endl;
    print_stats((unsigned char*)key_buffer.data(),NONCE_SIZE);
    print_stats((unsigned char*)key_buffer.data()+NONCE_SIZE,CC20_KEY_SIZE);

    input_buffer.data()[5] = 'h';
    input_buffer.data()[6] = 'e';
    input_buffer.data()[7] = 'y';

    cout<<"\nBefore encrypt: "<<endl;
    cout<<"Input buffer "<<endl;
    print_stats((unsigned char*)input_buffer.data(),iosize,0);
    cout<<"Output buffer "<<endl;
    print_stats((unsigned char*)output_buffer.data(),iosize,0);

    // Encrypt step
    cc20_utility::pure_crypt((unsigned char*)input_buffer.data(),(unsigned char*)output_buffer.data(),iosize,(unsigned char*)key_buffer.data());
    cout<<"\nAfter encrypt: "<<endl;
    cout<<"Input buffer "<<endl;
    print_stats((unsigned char*)input_buffer.data(),iosize,0);
    cout<<"Output buffer "<<endl;
    print_stats((unsigned char*)output_buffer.data(),iosize,0);

    // Decrypt step
    cc20_utility::pure_crypt((unsigned char*)output_buffer.data(),(unsigned char*)input_buffer.data(),iosize,(unsigned char*)key_buffer.data());
    cout<<"\nAfter decrypt: "<<endl;
    cout<<"Output buffer "<<endl;
    print_stats((unsigned char*)output_buffer.data(),iosize,0);
    cout<<"Input buffer "<<endl;
    print_stats((unsigned char*)input_buffer.data(),iosize,0);
    return 1;
  }


} // namespace testing
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
#ifndef WEB_RELEASE_LINUX_TEST
  string infile,oufile,nonce;
  c20::config configs = rd_inp(argc,argv,&infile);
  if (configs.arg_c!=2){
    cout<<"Must have 1 file input, -h for help."<<endl;
    return 0;
  }
  cmd_enc(infile,"", configs);
#else // start linux web test
  if(argc < 2){
    cout<<"Must have 1 input to start testing. \n \"1\" for curve test. \n "
          "\"2\" for encryption test. \n "
          "\"3\" for scrypt test. \n "
          "\"4\" for mobile release. \n "
          "\"5\" for pure crypt test. \n "
          <<endl;
    return 0;
  }
  if(stoi(argv[1]) == 1){
    cout<<"Curve test for web release.\n"<<endl;
    web_test::curve_test();
  }
  else if (stoi(argv[1]) == 2){
    cout<<"Encryption test for web release.\n"<<endl;

    std::string pas = "1234";
    std::string pas2 = "12345";
    std::string msg = "hello this is a message";

    web_test::test_enc_dec(pas,msg);
  }
  else if (stoi(argv[1]) == 3){
    cout<<"Scrypt Test.\n"<<endl;

    std::string pas = "1234";
    std::string msg = "hello this is a messagehello this is a messagehello this is a message";
    string out1 = scrypt(pas);
    string out2 = scrypt(msg);

    cout<<"#1: \""<< pas<<"\"\n"<<endl;
    cout<<"#1 out: \""<< out1<<"\"\n"<<endl;
    cout<<"#2: \""<< msg<<"\"\n"<<endl;
    cout<<"#2 out: \""<< out2<<"\"\n"<<endl;
  }
  else if (stoi(argv[1]) == 4){

    cout<<"Encryption test for mobile release.\n"<<endl;

    std::string pas = "1234";
    std::string msg = "hello this is a message";
    web_test::test_scrypt(pas, msg);
  }
  else if (stoi(argv[1])==5) {
    cout<<"Pure xor Encryption test.\n"<<endl;
    web_test::pure_crypt_test();
  }
  else {
   cout<<"Command not found, exiting."<<endl;
  }
#endif
  return 0;
}
//#endif // HAS_MAIN