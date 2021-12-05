#include <stdio.h>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <stdlib.h>
#include "cc20_file.h"

using namespace std;

int main(int argc, char **argv)
{
  string k="";
  cout << "File: \n";
  getline(cin, k);

  // ENCRYPTION TEST
  cc20_file a(k.data());
  a.run_test(k.data());
  cout << "Test finish."<<endl;

  return 1;
}