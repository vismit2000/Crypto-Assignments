#!/usr/bin/env python

###  Call syntax:
###
###       python3 CRACK.py ciphertext.txt recoveredtext.txt
###
###  The decrypted output is deposited in the file 'recoveredtext.txt'

import sys
from BitVector import *                                         

if len(sys.argv) is not 3:                                     
    sys.exit('''Needs two command-line arguments, one for '''
             '''the encrypted file and the other for the '''
             '''decrypted output file''')

PassPhrase = "I want to learn cryptograph and network security"

BLOCKSIZE = 64                                             
numbytes = BLOCKSIZE // 8       

def convertHexToBinary(str):
    '''
    This function takes a hexadecimal string as input and returns its binary equivalent
    '''
    binary_string = ""
    scale = 16 ## equals to hexadecimal
    for i in range(0, len(str)):
        char = bin(int(str[i], scale))[2:].zfill(4)
        binary_string += char
    return binary_string

def xorString(a, b):
    '''
    This functions returns the xor of two bitstrings
    '''
    y = int(a, 2)^int(b,2)
    return bin(y)[2:].zfill(len(a))

def findMax(lst):
    '''
    This functions returns the string with maximum frequency in the list
    '''
    freq = {}

    for i in range(len(lst)):
        if lst[i] in freq:
            freq[lst[i]] += 1
        else:
            freq[lst[i]] = 1

    best = 0
    ret = None

    for key, value in freq.items():
        if value > best:
            best = value
            ret = key

    return ret

# Create a bitvector from the ciphertext hex string:
FILEIN = open(sys.argv[1])                                   
encrypted = FILEIN.read().rstrip("\n")

# Convert ciphertext in hexadecimal to binary
bin_string = convertHexToBinary(encrypted)

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                     
for i in range(0,len(PassPhrase) // numbytes):                  
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]           
    bv_iv ^= BitVector( textstring = textstr )                        

# Divide the cipher binary string into blocks of BLOCKSIZE
ciphertextBlocks = []
for i in range(0, len(bin_string), BLOCKSIZE):
    ciphertextBlocks.append(BitVector(bitstring = bin_string[i : i+BLOCKSIZE]))

ciphertextBlocks.insert(0, bv_iv)

plaintextXORkey = []

ciphertextBlocksLength = len(ciphertextBlocks)
for i in range(ciphertextBlocksLength-1, 0, -1):
    plaintextXORkey.append(ciphertextBlocks[i]^ciphertextBlocks[i-1])

# Reverse the plaintextXORkey
plaintextXORkey = plaintextXORkey[::-1]

# LAUNCHING MODIFIED VIGENERE CIPHER ATTACK

###
## In Vigenere cipher, we get cipher blocks encrypted as (plaintext + key) % 26,
## but here we have blocks of plaintext XOR key
###

# Prepare VigenereTableau

ROWS = BLOCKSIZE // 8   # Hence ROWS = 8

VigenereTableau = [[] for i in range(ROWS)]

for i in range(len(plaintextXORkey)):
    temp = str(plaintextXORkey[i])
    for j in range(0, len(temp), numbytes):
        VigenereTableau[j//8].append(temp[j : j+numbytes])

key = ""

##### VERY IMPORTANT ASSUMPTION

# Assuming occurence of <space> in plaintext is maximum
# <space> is encoded as 20H in hexadecimal and 00100000 in binary

##### DUE TO ASSUMPTION, IT IS POSSIBLE THAT ONLY PARTIALLY CORRECT PLAINTEXT IS GENERATED

for i in range(ROWS):
    pxorkMax = findMax(VigenereTableau[i])
    ki = xorString(pxorkMax, '00100000')
    key += ki

key_bv = BitVector(bitstring = key)

############

# Now by CHOSEN PLAINTEXT ATTACK, we have got key as well as ciphertext. So simply decrypt the ciphertext
# as done in Decrypt.py

############

# Create a bitvector for storing the output plaintext bit array:
msg_decrypted_bv = BitVector( size = 0 )           

FILEIN = open(sys.argv[1])                                   
encrypted = BitVector( hexstring = FILEIN.read().rstrip("\n") )     
# print(encrypted)
# Carry out differential XORing of bit blocks and decryption:
prev_decrypted_block = bv_iv                                
for i in range(0, len(encrypted) // BLOCKSIZE):              
    bv = encrypted[i*BLOCKSIZE:(i+1)*BLOCKSIZE]              
    # bv = BitVector( texttring = bv )
    tempo = bv.deep_copy()                                       
    bv ^=  prev_decrypted_block                             
    prev_decrypted_block = tempo                             
    bv ^=  key_bv       
    # print(bv)                                        
    msg_decrypted_bv += bv                                      

# print(msg_decrypted_bv)
output_plaintext = msg_decrypted_bv.getTextFromBitVector()          
#print(outputtext)

# Write the plaintext to the output file:
FILEOUT = open(sys.argv[2], 'w')                               
FILEOUT.write(output_plaintext)                                      
FILEOUT.close()                                                
