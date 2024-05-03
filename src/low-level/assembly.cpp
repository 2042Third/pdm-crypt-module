//
// Created by Mike Yang on 2024/5/3.
//

#include "assembly.h"

#include <cstdint>

#ifdef __x86_64__
#include <x86intrin.h>
#endif

std::uint64_t assembly::get_timestamp_counter() {
#ifdef __x86_64__
  std::uint32_t lo, hi;
    asm volatile(
        "mfence"
        "rdtsc\n\t"
        "mov %%eax, %0\n\t"
        "mov %%edx, %1\n\t"
        : "=r"(lo), "=r"(hi)
        :
        : "eax", "edx", "memory"
    );
    return static_cast<std::uint64_t>(hi) << 32 | lo;
#else
  return static_cast<std::uint64_t>(-1);
#endif
}