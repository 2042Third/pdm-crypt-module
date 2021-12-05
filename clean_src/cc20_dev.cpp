/*
cc20_dev.cpp

pdm/Personal Data Management system is a encrypted and multiplatform data searching, building, archiving tool.

author:     Yi Yang
            5/2021
*/

#include "pdm-service.hpp"
#include <iostream>
#include <climits>
#include <ostream>
#include <random>
#include <wchar.h>

#ifdef DEEP_DEBUG
#include <iomanip>
#include <iostream>
#endif

#ifdef MACOS
#include <unistd.h>
#include <termios.h>
#endif

#ifdef LINUX
#include <unistd.h>
#ifndef WINDOWS
// #include <termios.h>
#endif 
#endif

#ifdef WINDOWS
#include <locale.h>
#include <windows.h>
#define _MBCS
#include <io.h>
#include <fcntl.h>

#endif

using namespace std;
unsigned int i=0;


void stream(uint8_t * key, uint8_t * nonce, uint32_t count,uint8_t*plain,unsigned int len);

#define U32T8_S(p, v)    \
  {                            \
    (p)[0] = (v >> 0) & 0xff;  \
    (p)[1] = (v >> 8) & 0xff;  \
    (p)[2] = (v >> 16) & 0xff; \
    (p)[3] = (v >> 24) & 0xff; \
  }

#define U8T32_S(p)                              \
  (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | \
   ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

// INT should only be unsigned, no checks here.
template <typename NT> 
void roln(NT &val,unsigned int n) {
    val= (val << n) | (val >> (32-n));
}

template <> 
void roln<uint32_t>(uint32_t &val,unsigned int n) {
    val= (val << n) | (val >> (32-n));
}

//algo change #2
static inline uint32_t rotl32(uint32_t x, int n)
{
  // http://blog.regehr.org/archives/1063
  return x << n | (x >> (-n & 31));
}

void endicha(uint8_t *a, uint32_t *b){
  for (i=0; i<16;i++){
    U32T8_S(a+4*i,b[i]);

  }
}

void expan(uint32_t * ot, unsigned int off, const uint8_t* in, unsigned int n) {
  for(i=0;i<n;i++){
    ot[off+i] = U8T32_S(in+4*i);
  }
}

// Operate a quarter-round chacha state on total of 16 bytes or 4 32-bit numbers at a time.
void quarteround(uint32_t * x, uint32_t a, uint32_t b, uint32_t c, uint32_t d){

  x[a] += x[b];
  x[d] = rotl32(x[d] ^ x[a], 16);
  x[c] += x[d];
  x[b] = rotl32(x[b] ^ x[c], 12);
  x[a] += x[b];
  x[d] = rotl32(x[d] ^ x[a], 8);
  x[c] += x[d];
  x[b] = rotl32(x[b] ^ x[c], 7);
}

void tworounds(uint32_t * state){
    quarteround(state, 0, 4, 8, 12) ;
    quarteround(state, 1, 5, 9, 13) ;
    quarteround(state, 2, 6, 10, 14);
    quarteround(state, 3, 7, 11, 15);
    quarteround(state, 0, 5, 10, 15);
    quarteround(state, 1, 6, 11, 12);
    quarteround(state, 2, 7, 8, 13) ;
    quarteround(state, 3, 4, 9, 14) ;
}
#ifdef PRINTING
// Print a hex unsigned number
template <typename NT> 
void p_hex (NT i){
    cout<<" 0x";cout<<setfill('0')<<setw(8)<<hex<<right<<i<<flush;

}
template <> 
void p_hex<uint8_t> (uint8_t i){
    cout<<dec<<i<<flush;
}

// Print a chacha state
template <typename NT> 
void p_state (NT * state){
    for(i=0; i<16;i++){
        p_hex(state[i]);
        if((i+1)%4==0)cout<<"\n";
    }
    cout<<endl;
}
template <> 
void p_state<uint8_t> (uint8_t * state){
    int n=16;
    for(unsigned int i=0; i<64;i++){
        // if((i+1)%n==0)cout<<setw(1)<<right<<"\t";
        p_hex(state[i]);
        if((i+1)%n==0)cout<<"\n";
    }
    cout<<endl;
}
#endif

template<typename NT>
void state_cpy(NT *a,NT*b,unsigned int n){
    for(unsigned int i=0; i<n;i++) a[i]=b[i];
}

/*
    Require: key has 8, nonce has 3, and count has 1 elements. 
*/
// void one_block (uint32_t*state, uint8_t* nex){
//     uint32_t folow[17];
//     memcpy(folow,state,sizeof(uint32_t)*16);
//     for (unsigned int i=0; i<10;i++) tworounds(folow);      // 20 rounds
//     set_conc(state,folow,16);
//     endicha(nex,folow);  
// }



//                     8              3                1
//                     32             12               4
//                     key            nonce            count

// void chasetup(uint8_t * key, uint8_t * nonce, uint32_t count,uint8_t* nex, uint32_t*cy){
//     cy[12] = count;
//     one_block(cy,nex);
// }



void init_byte (Bytes & a, int n){
    for (int i=0;i<n;i++) a.push_back((uint8_t) 0);
} 
void init_byte_rand_cc20 (Bytes & a, int n){
    for (int i=0;i<n;i++) {
        random_device rd;   // non-deterministic generator
        mt19937 gen(rd());
        a.push_back((uint8_t) gen());
    }
} 

void filterin(unsigned char * r){
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
}

// void poly35(uint8_t * key, Bytes plain, uint8_t*auth){
//     uint8_t pri[45] = {0x1,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7
//             ,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x3};
//     uint8_t cons[8]={0x3,0x3,0x2,0x0,0x6,0x1,0x7,0x0};
//     uint8_t acc[18];
//     init_byte(acc,17);

//     for (unsigned int i=0; i<(unsigned int)plain.size()/32;i++){
//         n = plain().data()[i*2+16]|0x1;
//         acc += plain().data()i*2;

//     }
// }

void outpt(int n){

    string in;
    if (n==1){
        #ifdef CHN
        // cout<<"请输入需要加密的文件名（pdm.exe 所在文件夹）：";
        // #ifdef WINDOWS
        const std::wstring tmp[2048] = L"请输入需要加密的文件名（所在文件夹）：";
        wcout<<L"请输入需要加密的文件名（所在文件夹）：";

        // #endif
        #endif
        #ifdef ENG
        std::cout << "Enter the file you want to encrypt: ";
        #endif
    }
    else if(n==2){
        #ifdef CHN
        std::cout << "请输入加密后的文件名（如过与以上文件相同，此文件将被删除代替）：";
        #endif
        #ifdef ENG
        std::cout << "Enter the file name of the encrypted file: ";
        #endif
    }
    else if(n==3){
        #ifdef CHN
        std::cout << "\n请输入密码（最多32个英文字母，数字组合）：";
        #endif
        #ifdef ENG
         std::cout << "Enter the key/password: ";
        #endif
    }
    else if(n==4){
        #ifdef CHN
        std::cout << "输入\"y\" 继续加密，或 \"n\" 取消此次加密（\"h\"更多选项）：";
        #endif
        #ifdef ENG
         std::cout << "enter \"y\" to encrypt otherwise \"n\" or \"h\" to cancel or more options: ";
        #endif
    }
    else if(n==5){
        #ifdef CHN
        cout<<"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n---------------------------------------------------------------------\n";
        cout<<"-------------pdm-crypt 个人数据管理工具-chacha20独立加密部分---------\n\n";
        std::cout << "-此免费软件仅供个人使用，如丢失密码或覆盖文件，用户自己负责。\n";
        cout<<"-此加密软件还在维护阶段，一些功能还未完善，为保证数据安全，请勿用同一密码\n加密多个文件。此行为普通情况下不会出现问题，但是如果数据入侵者对\nchacha20加密协议了解，此人员可以通过这两个文件来计算密码。\n";
        cout<<"-待完善部分（不影响数据安全）：\n\tpoly-1305（数据hash校对），\n\taead协议\n\n";
        cout<<"-待完善部分（影响数据安全，如果多次使用同一个密码）：\n\t 允许用户输入单次数字\n";
        cout<<"-\t\t\t\t\t\t\t杨译  2021\n";
        cout<<"\n\n\n\n回车返回\n";
        std::getline(std::cin, in);
        #endif
        #ifdef ENG
        std::cout << "pdm-crypt";
        std::getline(std::cin, in);
        #endif
    }
    else if(n==6){
        #ifdef CHN
        cout<<"!!!请保存此独立数字秘符，只能用此独立数字秘府和密码来解锁此文件：\n";
        #endif
        #ifdef ENG
         std::cout << "Copy this nonce passcode, for decryption: \n";
        #endif
    }
    else if(n==7){
        #ifdef CHN
        cout<<"请输入这次加密的独立数字秘府，支持任何数字，但请不要多次使用\n同样的独立数字与密码组合（或选择自动生成，输入回车）：";
        #endif
        #ifdef ENG
         std::cout << "Enter nonce, a number passcode specific to this encryption,\n do not reuse this password and number passcode pair (press enter to generate one ): \n";
        #endif
    }
    else if(n==8){
        #ifdef CHN
        cout<<"任何键退出\n";
        std::getline(std::cin, in);
        #endif
        #ifdef ENG
         std::cout << "Press any key to exit\n";
        std::getline(std::cin, in);
        #endif
    }

}

int usrinp(string a,string b){
    string in;
    #ifdef CHN
    if(a==b)cout<< "将会删除代替 "<<a<<" 如果失去密码，文件将丢失！\n";
    else cout<<"添加加密文件 "<<b;
    std::cout << " 是否加密 "<<a<<"? \n";
    #endif
    #ifdef ENG
    if(a!=b)cout<< "Replacing "<<a<<" with a encrypted version! ";
    else cout<<"Adding encrypted file "<<b;
    std::cout << " encrypt "<<a<<"? \n";
    #endif
    outpt(4);
    std::getline(std::cin, in);
    if(in=="n"){
        return 0;
    }
    else if(in=="h"){
        outpt(5);
        return usrinp(a,b);
    }
    else if (in=="y"){
        return 1;
    }
    else{
        return 0;
    }
    return 1;
}
