
#ifndef PDM_CC20_FILE_H
#define PDM_CC20_FILE_H

#include "cpp-mmf/memory_mapped_file.hpp"

class cc20_file {
public:
  void read_new(const char* f_name);
  void write_new(const char* f_name, int overwrite);
  void run_test(const char* f_name);
  void unmap(){if(source_mf !=NULL)source_mf->unmap();}
  size_t file_size(){return source_mf->file_size();}
  const char* get_mapping(){ 
    source_mf->map(0, source_mf->file_size());
    return source_mf->data();
  }
  memory_mapped_file::read_only_mmf get_read();
  cc20_file (const char* f_name);
  cc20_file (){}
  ~cc20_file();
private:
  memory_mapped_file::read_only_mmf* source_mf = NULL;
  memory_mapped_file::writable_mmf* dest_mf = NULL;
};

#endif