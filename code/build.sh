#!/bin/bash
# Build Rsa project
gcc -Wall main.cpp rsa_gmp.cpp -I../gmp -lgmp -O2 -o Rsa
./Rsa
exit 0 
