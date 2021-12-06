#include <stdio.h>
#include <string>
#include <vector>
#include "cc20_multi.h"
#include "cc20_poly.hpp "
#include <iostream>
#include <sstream>
#include <stdlib.h>

using namespace std;

int main(int argc, char **argv)
{
  string k="";
  string v="";
  cout << "Key: \n";
  getline(cin, k);
  cout << "File: \n";
  getline(cin, v);

  Bytes cur ;
  init_byte_rand_cc20(cur,12);
  nonce="1";
  // ENCRYPTION TEST
  vector<char> outstr;
  outstr.reserve(v.size()+13);
  cmd_enc(v,"t_out",cur);


}