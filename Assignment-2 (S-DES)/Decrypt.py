###  Call syntax:
###
###       Decrypt.py  CIPHERTEXT.txt  output.txt
###
###  The decrypted output is deposited in the file 'output.txt'

import sys

# if len(sys.argv) is not 3:                                                  
#     sys.exit('''Needs two command-line arguments, one for '''
#              '''the encrypted file and the other for the '''
#              '''decrypted output file''')

# Take key as input
if __name__ == "__main__":
    KEY = input('Please specify key to use (10 bits):')
else:
    KEY = '1001001001'

IP1 = [7, 6, 4, 0, 2, 5, 1, 3]
IP1_inverse = [3, 6, 4, 7, 2, 5, 1, 0]
PC1 = [9, 7, 3, 8, 0, 2, 6, 5, 1, 4]
PC2 = [3, 1, 7, 5, 0, 6, 4, 2]
sel_table = [0, 2, 1, 3, 0, 1, 2, 3]
P = [1, 0, 3, 2]

key1 = []
key2 = []

S0 = [[0 for x in range(4)] for y in range(4)] 
S1 = [[0 for x in range(4)] for y in range(4)] 

S0[0][0] = [0, 1]
S0[0][1] = [0, 0]
S0[0][2] = [1, 0]
S0[0][3] = [1, 1]
S0[1][0] = [1, 1]
S0[1][1] = [0, 1]
S0[1][2] = [0, 0]
S0[1][3] = [1, 0]
S0[2][0] = [1, 0]
S0[2][1] = [0, 0]
S0[2][2] = [1, 1]
S0[2][3] = [0, 1]
S0[3][0] = [0, 1]
S0[3][1] = [1, 1]
S0[3][2] = [1, 0]
S0[3][3] = [0, 0]

S1[0][0] = [0, 0]
S1[0][1] = [1, 1]
S1[0][2] = [0, 1]
S1[0][3] = [1, 0]
S1[1][0] = [1, 1]
S1[1][1] = [1, 0]
S1[1][2] = [0, 0]
S1[1][3] = [0, 1]
S1[2][0] = [0, 1]
S1[2][1] = [0, 0]
S1[2][2] = [1, 1]
S1[2][3] = [1, 0]
S1[3][0] = [1, 0]
S1[3][1] = [0, 1]
S1[3][2] = [1, 1]
S1[3][3] = [0, 0]

def rotate(lst, n):
    return lst[n:] + lst[:n]

# Round Key Generation
def genkeys():
    C0 = [KEY[PC1[0]], KEY[PC1[1]], KEY[PC1[2]], KEY[PC1[3]], KEY[PC1[4]]]
    D0 = [KEY[PC1[5]], KEY[PC1[6]], KEY[PC1[7]], KEY[PC1[8]], KEY[PC1[9]]]

    C1 = rotate(C0, 1)
    D1 = rotate(D0, 1)

    C1D1 = C1 + D1

    for i in PC2:
        key1.append(C1D1[i])

    C2 = rotate(C1, 2)
    D2 = rotate(D1, 2)

    C2D2 = C2 + D2

    for i in PC2:
        key2.append(C2D2[i])

# Decryption

def E(inp):
    op = []
    for i in sel_table:
        op.append(inp[i])
    return op

def f(R, K):
    ER = E(R)
    ER_XOR_K = []
    
    for i in range(8):
        ER_XOR_K.append(str(int(ER[i]) ^ int(K[i])))
    
    S0_ip_x = ER_XOR_K[0] + ER_XOR_K[3]
    S0_ip_x = int(S0_ip_x, 2)
    
    S0_ip_y = ER_XOR_K[1] + ER_XOR_K[2]
    S0_ip_y = int(S0_ip_y, 2)
    
    S1_ip_x = ER_XOR_K[4] + ER_XOR_K[7]
    S1_ip_x = int(S1_ip_x, 2)
    
    S1_ip_y = ER_XOR_K[5] + ER_XOR_K[6]
    S1_ip_y = int(S1_ip_y, 2)
    
    S_out = S0[S0_ip_x][S0_ip_y] + S1[S1_ip_x][S1_ip_y]
    
    OUT = []
    
    for i in P:
        OUT.append(S_out[i])
    
    return OUT

def decrypt(CT):
    L0 = []
    R0 = []

    for i in IP1[:4]:
        L0.append(CT[i])

    for i in IP1[4:]:
        R0.append(CT[i])

    L1 = R0
    fRK = f(R0, key2)

    R1 = []
        
    for i in range(4):
        R1.append(str(int(L0[i]) ^ int(fRK[i])))

    L2 = R1
    fRK2 = f(R1, key1)

    R2 = []
        
    for i in range(4):
        R2.append(str(int(L1[i]) ^ int(fRK2[i])))

    final = R2 + L2

    op_left = []
    op_right = []

    for i in IP1_inverse[:4]:
        op_left.append(final[i])

    for i in IP1_inverse[4:]:
        op_left.append(final[i])
        
    output = op_left + op_right

    return output

# Read CIPHERTEXT from the file specified in argv[1]
if __name__ == "__main__":
    genkeys()
    fin = open(sys.argv[1], 'r')
else:
    genkeys()
    fin = open('CIPHERTEXT.txt', 'r')

if len(sys.argv) > 1:
    # Open file for writing
    fout = open(sys.argv[2], "w")

    line = fin.readline()[:-1]

    while line != '':
        fout.write(chr(int(''.join(decrypt(line)), 2)))
        line = fin.readline()[:-1]

    fin.close()
    fout.close()