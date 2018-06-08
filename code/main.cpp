
#include "rsa_gmp.h"


internal void
PrintMessage(char *Message, u32 Length)
{
    for(u32 Index = 0;
        Index < Length;
        ++Index)
    {
        printf("%c", Message[Index]);        
    }
    printf("\n");
}


int
main(void)
{    
    timespec Start, Finish;
    u64 Time;
    clock_gettime(CLOCK_MONOTONIC, &Start);

    mpz_t M;  mpz_init(M);
    mpz_t C;  mpz_init(C);
    mpz_t DC;  mpz_init(DC);
    private_key PrivateKey;
    public_key PublicKey;
    // Initialize public key
    mpz_init(PublicKey.N);
    mpz_init(PublicKey.E); 
    // Initialize private key
    mpz_init(PrivateKey.N); 
    mpz_init(PrivateKey.E); 
    mpz_init(PrivateKey.D); 
    mpz_init(PrivateKey.P); 
    mpz_init(PrivateKey.Q); 
    GenerateKeys(&PrivateKey, &PublicKey);
    

    char MessageForEncryption[BLOCK_SIZE] = "Hello world.";
    printf("Original message: ");
    PrintMessage(MessageForEncryption, 12);
    char EncryptedMessage[BLOCK_SIZE];    
    Encrypt(EncryptedMessage, MessageForEncryption, BLOCK_SIZE, &PublicKey);

    printf("Message after encryption: ");
    PrintMessage(EncryptedMessage, BLOCK_SIZE);

    char Message[BLOCK_SIZE];
    Decrypt(Message, EncryptedMessage, BLOCK_SIZE, &PrivateKey);

    printf("Message after decryption: ");
    PrintMessage(Message, 12);

    
    clock_gettime(CLOCK_MONOTONIC, &Finish);
    Time = (Finish.tv_sec - Start.tv_sec) * 1000000 + (Finish.tv_nsec - Start.tv_nsec) / 10000;    
    printf("\n");
    printf("\n");
    printf("TIME %llums.\n", Time);
    return(0); 
}
