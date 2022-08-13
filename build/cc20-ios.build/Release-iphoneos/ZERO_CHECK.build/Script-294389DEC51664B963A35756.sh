#!/bin/sh
set -e
if test "$CONFIGURATION" = "Debug"; then :
  cd /Users/mikeyang/Documents/pdm/pdm-crypt-module/build
  make -f /Users/mikeyang/Documents/pdm/pdm-crypt-module/build/CMakeScripts/ReRunCMake.make
fi
if test "$CONFIGURATION" = "Release"; then :
  cd /Users/mikeyang/Documents/pdm/pdm-crypt-module/build
  make -f /Users/mikeyang/Documents/pdm/pdm-crypt-module/build/CMakeScripts/ReRunCMake.make
fi
if test "$CONFIGURATION" = "MinSizeRel"; then :
  cd /Users/mikeyang/Documents/pdm/pdm-crypt-module/build
  make -f /Users/mikeyang/Documents/pdm/pdm-crypt-module/build/CMakeScripts/ReRunCMake.make
fi
if test "$CONFIGURATION" = "RelWithDebInfo"; then :
  cd /Users/mikeyang/Documents/pdm/pdm-crypt-module/build
  make -f /Users/mikeyang/Documents/pdm/pdm-crypt-module/build/CMakeScripts/ReRunCMake.make
fi

