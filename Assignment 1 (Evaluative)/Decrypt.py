#!/usr/bin/env python

###  Call syntax:
###
###       python3 Decrypt.py ciphertext.txt output.txt
###
###  The decrypted output is deposited in the file 'output.txt'

import sys
from BitVector import *                                         

if len(sys.argv) is not 3:                                     
    sys.exit('''Needs two command-line arguments, one for '''
             '''the encrypted file and the other for the '''
             '''decrypted output file''')

PassPhrase = "I want to learn cryptograph and network security"

BLOCKSIZE = 64                                             
numbytes = BLOCKSIZE // 8                                       

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                     
for i in range(0,len(PassPhrase) // numbytes):                  
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]           
    bv_iv ^= BitVector( textstring = textstr )                        

# Get key from user:
key = None
if sys.version_info[0] == 3:                                               
    key = input("\nEnter key: ")                                          
else:                                                                         
    key = raw_input("\nEnter key: ")                                        
key = key.strip()                                                                            

# Reduce the key to a bit array of size BLOCKSIZE:
key_bv = BitVector(bitlist = [0]*BLOCKSIZE)                   
for i in range(0,len(key) // numbytes):                        
    keyblock = key[i*numbytes:(i+1)*numbytes]                 
    key_bv ^= BitVector( textstring = keyblock )          

# Create a bitvector from the ciphertext hex string:
FILEIN = open(sys.argv[1])                                   
encrypted = BitVector( hexstring = FILEIN.read().rstrip("\n") )   

# Create a bitvector for storing the output plaintext bit array:
msg_decrypted_bv = BitVector( size = 0 )           

# Carry out differential XORing of bit blocks and decryption:
prev_decrypted_block = bv_iv                                
for i in range(0, len(encrypted) // BLOCKSIZE):              
    bv = encrypted[i*BLOCKSIZE:(i+1)*BLOCKSIZE]              
    tempo = bv.deep_copy()                                       
    bv ^=  prev_decrypted_block                             
    prev_decrypted_block = tempo                            
    bv ^=  key_bv                                               
    msg_decrypted_bv += bv                                      

output_plaintext = msg_decrypted_bv.getTextFromBitVector()          
#print(outputtext)

# Write the plaintext to the output file:
FILEOUT = open(sys.argv[2], 'w')                               
FILEOUT.write(output_plaintext)                                      
FILEOUT.close()                                                

