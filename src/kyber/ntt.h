//
// Created by Yi Yang on 2024/4/13.
//

#ifndef CC20_NTT_H
#define CC20_NTT_H


#include <vector>

class ntt {
public:
  void parse (const std::vector<uint8_t>& v, std::vector<uint8_t> & out) ;
private:
  int q = 3329;
};


#endif //CC20_NTT_H
