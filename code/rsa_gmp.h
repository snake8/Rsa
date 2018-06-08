#if !defined(RSA_GMP_H)

#include <gmp.h>
#include "shared_includes.h" 


// 1024-bits encryption. 

#define MODULUS_SIZE 1024                   // This is the number of bits we want in the modulus.
#define BLOCK_SIZE (MODULUS_SIZE / 8)         // This is the size of a block that gets en/decrypted at once. 
#define BUFFER_SIZE ((MODULUS_SIZE / 8) / 2)  // This is the number of bytes in n and p.



struct private_key
{
    mpz_t N; // NOTE(dan):  Mudules.                    *
    mpz_t E; //             Public Exponent.            *
    mpz_t D; //             Private Exponent.           *
    mpz_t P; //             Starting prime.             *
    mpz_t Q; //             Second starting pirme.      *
};


struct public_key
{
    mpz_t N; // NOTE(dan): Modules                      *
    mpz_t E; //            Public Exponent              *
};


void GenerateKeys(private_key *PrivateKey, public_key *PublicKey); 
s32 Encrypt(char Encrypt[], char Message[], u32 Length, public_key *PublicKey);
s32 Decrypt(char *Message, char *EncryptedMessage, u32 Length, private_key *PrivateKey);
void BlockEncrypt(mpz_t C, mpz_t M, public_key *PublicKey);
void BlockDecrypt(mpz_t C, mpz_t M, private_key *PrivateKey); 


#define RSA_GMP_H
#endif
