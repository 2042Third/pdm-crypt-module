#include <stdio.h>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <stdlib.h>

#include "c++/ed25519.h"
#include "c++/x25519.h"
#include "source/curve25519_mehdi.h"
#include "source/BaseTypes.h"
#include "source/base_folding8.h"
#include "pdm-service.hpp"
#include "cc20_dev.hpp"


using namespace std;

int main(int argc, char **argv)
{
  Bytes p1, p2, sec1, sec2, share;
  sec1.reserve(33);
  p1.reserve(33);
  // ED25519Private sec1_o(sec1,32);
  // ED25519Public p1_o(p1,32);
  X25519Private x();
  cout<< "secrect: "<< X25519Private().GetPrivateKey(0)<<endl;
  cout<< "public : "<< X25519Private().GetPublicKey(0)<<endl;
  cout << "Test finish."<<endl;

  return 1;
}