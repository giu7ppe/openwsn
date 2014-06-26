#ifndef __AES_H
#define __AES_H

#include "openwsn.h"

//=========================== define ==========================================



// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
// xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b}
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

uint8_t in[16], out[16], aes_state[4][4];

uint8_t RoundKey[240];

uint8_t Key[64];

uint8_t getSBoxValue(uint8_t num);

void KeyExpansion();

void AddRoundKey(uint8_t round);

void SubBytes();

void ShiftRows();

void MixColumns();

void AES_Cipher();

#endif
