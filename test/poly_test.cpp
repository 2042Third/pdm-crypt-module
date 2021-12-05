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
  cout << "Value: \n";
  getline(cin, v);

  // ENCRYPTION TEST
  vector<char> outstr;
  outstr.reserve(v.size()+13);
  cmd_enc((uint8_t *)((&v)->data()), v.size(), (uint8_t *)((&outstr)->data()), k);


}