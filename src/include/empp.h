/**
 * For pdm Android, after procrastinating for better half of a year; this header is indeed
 * needed.
 * Aug, 7, 2022
 * Yi Yang
 * */
#define C20_ECC_SIZE 32

#define C20_EXPORT extern "C"
#define cplusplus_main_compilation (__cplusplus & WEB_TEST)
#include <vector>
#include <iostream>
void memclear(uint8_t* a, size_t b );
std::string pp_hash(std::string user1, std::string user2);
const char* pp_hash_c(char* user1, char* user2);

C20_EXPORT
void pp_hash_convert(const char* user1, const char* user2, char* outstr);
void use_vector_string(const std::vector<uint8_t> &vec) ;

std::string loader_check(const std::string& key, std::string& input);
std::string checker_in(const std::string& key, const std::string& input);
std::string checker_out(const std::string& key, const std::string& inputi);
std::string scrypt(std::string a);
C20_EXPORT
void loader_check_convert(const char* key,  const char* input, size_t input_n, char* outstr);
std::string loader_out(std::string& key, const std::string& inputi);
C20_EXPORT
void loader_out_convert(const char* key,  const char* inputi, size_t inputi_n, char* outstr);
std::string gen_sec();
std::string gen_pub(std::string a);
std::string gen_shr(std::string a,  std::string c);
std::string get_hash(std::string a);
std::string get_hash_arr(const char* a, size_t asize);
namespace cc20_utility {
  static size_t nonce_key_pair_size () {return NONCE_SIZE+CC20_KEY_SIZE+1;}
  static void gen_byte_rand_cc20 (uint8_t * a, size_t n);
  static void gen_key_nonce_pair(uint8_t *a, size_t size);
  void pure_crypt(uint8_t*buf,uint8_t*outstr,size_t input_length,uint8_t*key_nonce);
}
namespace web_test{
  int test (const std::string& a, const std::string& b, int accum=-1);
  int test_scrypt (const std::string& a, const std::string& b, int accum=-1);
  int r_test(int count);
  int curve_test ();
}
C20_EXPORT
void get_hash_convert(const char* a, size_t a_n, char* outstr);