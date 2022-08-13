#!/bin/sh
set -e
if test "$CONFIGURATION" = "Debug"; then :
  cd /Users/mikeyang/Documents/pdm/pdm-crypt-module/build
  echo Build\ all\ projects
fi
if test "$CONFIGURATION" = "Release"; then :
  cd /Users/mikeyang/Documents/pdm/pdm-crypt-module/build
  echo Build\ all\ projects
fi
if test "$CONFIGURATION" = "MinSizeRel"; then :
  cd /Users/mikeyang/Documents/pdm/pdm-crypt-module/build
  echo Build\ all\ projects
fi
if test "$CONFIGURATION" = "RelWithDebInfo"; then :
  cd /Users/mikeyang/Documents/pdm/pdm-crypt-module/build
  echo Build\ all\ projects
fi

