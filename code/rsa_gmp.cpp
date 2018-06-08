
#include "rsa_gmp.h"

// NOTE(dan): Assumes mpz_t's are initted.
void
GenerateKeys(private_key *PrivateKey, public_key *PublicKey)
{
    char Buffer[MODULUS_SIZE];
    u32 Index;
    mpz_t Phi; mpz_init(Phi);
    mpz_t Tmp1; mpz_init(Tmp1);
    mpz_t Tmp2; mpz_init(Tmp2);
    srand(time(NULL));
    mpz_set_ui(PrivateKey->E, 0x10001);
    for(Index = 0;
        Index < BUFFER_SIZE;
        ++Index)
    {
        Buffer[Index] = rand() % 0xFF;
    }    
    Buffer[0] |= 0xC0; // NOTE(dan): Set the top two bits to 1 to ensure int(tmp) is relatively large.
    Buffer[BUFFER_SIZE - 1] |= 0x01;
    mpz_import(Tmp1, BUFFER_SIZE, 1, sizeof(Buffer[0]), 0, 0, Buffer); // NOTE(dan): Interpret this char buffer as an int.
    mpz_nextprime(PrivateKey->P, Tmp1); // NOTE(dan): Choose next prime starting from random generated PrivateKey->P. 
    mpz_mod(Tmp2, PrivateKey->P, PrivateKey->E);
    while(!mpz_cmp_ui(Tmp2, 1))         
    {
        mpz_nextprime(PrivateKey->P, PrivateKey->P);    // NOTE(dan): So choose the next prime.
        mpz_mod(Tmp2, PrivateKey->P, PrivateKey->E);
    }
    // NOTE(dan): Now we selecting Q(Ending prime number.).
    do
    {
        for(Index = 0;
            Index < BUFFER_SIZE;
            ++Index)
        {
            Buffer[Index] = rand() % 0xFF;
            Buffer[0] |= 0xC0;
            Buffer[BUFFER_SIZE - 1] |= 0x01;
            mpz_import(Tmp1, (BUFFER_SIZE), 1, sizeof(Buffer[0]), 0, 0, Buffer);
            mpz_nextprime(PrivateKey->Q, Tmp1);            
            mpz_mod(Tmp2, PrivateKey->Q, PrivateKey->E);
            while(!mpz_cmp_ui(Tmp2, 1))         
            {
                mpz_nextprime(PrivateKey->Q, PrivateKey->Q);    
                mpz_mod(Tmp2, PrivateKey->Q, PrivateKey->E);
            }            
        }
    } while(mpz_cmp(PrivateKey->P, PrivateKey->Q) == 0);
    // NOTE(dan): On this stage we found two prime numbers.
    mpz_mul(PrivateKey->N, PrivateKey->P, PrivateKey->Q); // NOTE(dan): Compute N = P * Q.
    // NOTE(dan): Calculating Phi = (P - 1) * (Q - 1).
    mpz_sub_ui(Tmp1, PrivateKey->P, 1);
    mpz_sub_ui(Tmp2, PrivateKey->Q, 1);
    mpz_mul(Phi, Tmp1, Tmp2);
    // NOTE(dan):  Calculate decryption key (multiplicative inverse of E mod Phi).
    if(!mpz_invert(PrivateKey->D, PrivateKey->E, Phi))
    {
        mpz_gcd(Tmp1, PrivateKey->E, Phi);
        printf("gcd(e, phi) = [%s]\n", mpz_get_str(NULL, 16, Tmp1));
        printf("Invert failed\n");
    }
    // NOTE(dan): Set public key.
    mpz_set(PublicKey->E, PrivateKey->E);
    mpz_set(PublicKey->N, PrivateKey->N);
}



void
BlockEncrypt(mpz_t C, mpz_t M, public_key *PublicKey)
{
    mpz_powm(C, M, PublicKey->E, PublicKey->N); // NOTE(dan): C = M^e mod n.
}


void
BlockDecrypt(mpz_t M, mpz_t C, private_key *PrivateKey)
{
    mpz_powm(M, C, PrivateKey->D, PrivateKey->N); 
}

s32
Encrypt(char EncryptResult[], char Message[],
        u32 Length, public_key *PublicKey)
{
    u32 BlockCount = 0;
    u32 Prog = Length;
    char MessBlock[BLOCK_SIZE];
    mpz_t M; mpz_init(M);
    mpz_t C; mpz_init(C);
    while(Prog > 0)
    {
        u32 Index = 0;
        int D_Length = (Prog >= (BLOCK_SIZE - 11)) ? BLOCK_SIZE - 11 : Prog;
        MessBlock[Index++] = 0x00;
        MessBlock[Index++] = 0x02;
        while(Index < (BLOCK_SIZE - D_Length - 1))
        {
            MessBlock[Index++] = (rand() % (0xFF - 1)) + 1; 
        }
        MessBlock[Index++] = 0x00;
        memcpy(MessBlock + Index, Message + (Length - Prog), D_Length);
        mpz_import(M, BLOCK_SIZE, 1, sizeof(MessBlock[0]), 0, 0, MessBlock);
        BlockEncrypt(C, M, PublicKey);
        u32 Off = BlockCount * BLOCK_SIZE;
        Off += (BLOCK_SIZE - (mpz_sizeinbase(C, 2) + 8 - 1) / 8);
        mpz_export(EncryptResult + Off, NULL, 1, sizeof(char), 0, 0, C);
        BlockCount++;
        Prog -= D_Length; 
    }
    return(BlockCount * BLOCK_SIZE);
}

s32
Decrypt(char *Message, char *EncryptedMessage,
        u32 Length, private_key *PrivateKey)
{
    u32 MsgIndex = 0;
    char Buffer[BLOCK_SIZE];
    *(long long*)Buffer = 0x0ll;
    mpz_t C; mpz_init(C);
    mpz_t M; mpz_init(M);
    for(u32 Index = 0;
        Index < (Length / BLOCK_SIZE);
        ++Index)
    {
        mpz_import(C, BLOCK_SIZE, 1, sizeof(char), 0, 0, EncryptedMessage + Index * BLOCK_SIZE);
        BlockDecrypt(M, C, PrivateKey);
        int Off = (BLOCK_SIZE - (mpz_sizeinbase(M, 2) + 8 - 1) / 8); 
        mpz_export(Buffer + Off, NULL, 1, sizeof(char), 0, 0, M);
        u32 Index2 = 0;
        for(Index2 = 2;
            ((Buffer[Index2] != 0) && (Index2 < BLOCK_SIZE));
            ++Index2);
        ++Index2;
        memcpy(Message + MsgIndex, Buffer + Index2, BLOCK_SIZE - Index2);
        MsgIndex += BLOCK_SIZE - Index2; 
    }
    return(MsgIndex);
}

