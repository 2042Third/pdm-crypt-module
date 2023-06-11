//
// Created by Yi Yang on 12/9/2022.
//

#ifndef CC20_CC20_DEV_H
#define CC20_CC20_DEV_H

#include "types.h"
#include <string>
#include <iterator>



namespace cc20_dev {
  template<typename NU> void set_conc (NU* s1,NU* s2,unsigned int n){
    for(unsigned int i=0;i<n;i++)s1[i]+=s2[i];
  }
  template<typename NU> void set_xor(NU* s1,NU* s2,unsigned int n,unsigned int off);
  Bytes stob (std::string &src);
  std::string btos (Bytes &src);
  void init_byte_rand_cc20 (Bytes & a, int n);
  std::string pad_to_key(const std::string &text_key, int len);
  uint32_t upper(uint64_t a);
  uint32_t lower(uint64_t a);
  void expan(uint32_t *ot, unsigned int off, const uint8_t *in, unsigned int n);
  void quarteround(uint32_t *x, uint32_t a, uint32_t b, uint32_t c, uint32_t d);
  void tworounds(uint32_t *state);
  
  
  inline uint32_t rotl32(uint32_t x, int n)
  {
    // http://blog.regehr.org/archives/1063
    return x << n | (x >> (-n & 31));
  }

}
#define U32T8_S(p, v)    \
  {                            \
    (p)[0] = ((v) >> 0) & 0xff;  \
    (p)[1] = ((v) >> 8) & 0xff;  \
    (p)[2] = ((v) >> 16) & 0xff; \
    (p)[3] = ((v) >> 24) & 0xff; \
  }

#define U8T32_S(p)                              \
  (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | \
   ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
template <typename Iterator>
struct hex_iterator_traits {
  typedef typename std::iterator_traits<Iterator>::value_type value_type;
};

template<typename Container>
struct hex_iterator_traits< std::back_insert_iterator<Container> > {
  typedef typename Container::value_type value_type;
};

template<typename Container>
struct hex_iterator_traits< std::front_insert_iterator<Container> > {
  typedef typename Container::value_type value_type;
};

template<typename Container>
struct hex_iterator_traits< std::insert_iterator<Container> > {
  typedef typename Container::value_type value_type;
};

template<typename T, typename charType, typename traits>
struct hex_iterator_traits< std::ostream_iterator<T, charType, traits> > {
  typedef T value_type;
};

template <typename T, typename OutputIterator>
OutputIterator encode_one ( T val, OutputIterator out, const char * hexDigits ) {
  const std::size_t num_hex_digits =  2 * sizeof ( T );
  char res [ num_hex_digits ];
  char  *p = res + num_hex_digits;
  for ( std::size_t i = 0; i < num_hex_digits; ++i, val >>= 4 )
    *--p = hexDigits [ val & 0x0F ];
  return std::copy ( res, res + num_hex_digits, out );
}

template <typename T>
unsigned char hex_char_to_int ( T val ) {
  char c = static_cast<char> ( val );
  unsigned retval = 0;
  if      ( c >= '0' && c <= '9' ) retval = c - '0';
  else if ( c >= 'A' && c <= 'F' ) retval = c - 'A' + 10;
  else if ( c >= 'a' && c <= 'f' ) retval = c - 'a' + 10;
  return static_cast<char>(retval);
}
/**
 * Based on boost and sql functions that converts hex string to string
 *
 * */
template<typename InputIter, typename OutIter >
OutIter decode_one( InputIter &a1, InputIter a2 , OutIter out ){
  typedef typename hex_iterator_traits<OutIter>::value_type T;
  T res (0);
  for ( std::size_t i = 0; i < 2 * sizeof ( T ); ++i, ++a1 ) {
    res = ( 16 * res ) + hex_char_to_int (*a1);
  }

  *out = res;
  return ++out;
}
/**
* Based on boost and sql functions that converts hex string to string
*
* */
template<typename InputIter, typename OutIter >
OutIter htos_( InputIter a1, InputIter a2 , OutIter out ){
  while ( a1 != a2 )
    out = decode_one ( a1, a2, out);
  return out;
}
/**
 * Based on boost and sql functions that converts hex string to string
 *
 * */
template<typename OutIter >
OutIter htos_to(const std::string &a, OutIter out ){
  return htos_(a.begin(), a.end(), out);
}

/**
 * Based on boost and sql functions that converts hex string to string
 *
 * */
template<typename InputIter, typename OutIter >
OutIter hex_f( InputIter a1, InputIter a2 , OutIter out ){
  for ( ; a1 != a2; ++a1 )
    out = encode_one ( *a1, out, "0123456789abcdef" );
  return out;
}
/**
 * Based on boost and sql functions that converts hex string to string
 *
 * */
template<typename OutIter >
OutIter hex_from(const std::string &a, OutIter out ){
  return hex_f(a.begin(), a.end(), out);
}

#endif //CC20_CC20_DEV_H
