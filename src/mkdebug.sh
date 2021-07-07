#!/bin/bash
function macb {
  make enmac;
  echo "build enmac completed";
  make demac;
  echo "build demac completed";
} 

function linb {
  make en_debug;
  echo "build en completed";
  make de_debug;
  echo "build de completed";
}
mchin_c="$(uname -s)"
case ${mchin_c} in
  Darwin*) 
    echo "Darwin" 
    macb
    ;;
  Linux*)   
    echo "Linux"  
    linb
    ;;
  *)
    echo "No match "${mchin_c}
    ;;
esac


BSIZE=$(cat cc20_multi.cpp | grep "const int BLOCK_SIZE" | cut -d" " -f-7)
echo $BSIZE
