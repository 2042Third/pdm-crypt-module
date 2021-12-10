# pdm crypt module

The encryption/hashing module for all pdm programs.

## Table of Contents
  * [Install](#install)
  * [Documentation](#documentation)

## Install 
### Standalone
#### Windows Mingw
```
clean_src/mingw32-make windows
```
#### MacOs / GNU/Linux
```
clean_src/make en
```
### Wasm Module
*to be changed
```
clean_src/make en
```

## Documentation
### Compile Definitions
definition | -
-- | --
SINGLETHREADING | making the module to run single threaded; only used in wasm/web projects
LINUX | currently also needed for windows
