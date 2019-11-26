###  Call syntax:
###
###       python3 CRACK.py 
###
###  The main key, round1 subkey and round2 subkey are printed on screen

import sys
import Encrypt
import Decrypt

# if len(sys.argv) is not 3:                                     
#     sys.exit('''Needs two command-line arguments, one for '''
#              '''the encrypted file and the other for the '''
#              '''decrypted output file''')

IP1 = [7, 6, 4, 0, 2, 5, 1, 3]
IP1_inverse = [3, 6, 4, 7, 2, 5, 1, 0]

PC1 = [9, 7, 3, 8, 0, 2, 6, 5, 1, 4]
PC2 = [3, 1, 7, 5, 0, 6, 4, 2]
sel_table = [0, 2, 1, 3, 0, 1, 2, 3]

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

fkPermTable = [0 ,2 , 1, 3, 0, 1, 2, 3]
P = [1, 0, 3, 2]
S0_Table = [[1, 0, 2, 3], [3, 1, 0 ,2], [2, 0 , 3, 1], [1, 3, 2 ,0]]
S1_Table = [[0, 3, 1 , 2], [3, 2, 0, 1], [1, 0 , 3, 2], [2, 1, 3 , 0]]
DDT_S0 = [
                [16, 0, 0, 0],
                [0, 8, 4, 4],
                [0, 4, 12, 0],
                [4, 4, 0, 8],
                [0, 4, 0, 12],
                [4, 4, 8, 0],
                [0, 8, 4, 4],
                [8, 0, 4, 4],
                [2, 2, 10, 2],
                [4, 4, 0, 8],
                [10, 2, 2, 2],
                [0, 8, 4, 4],
                [2, 10, 2, 2],
                [8, 0, 4, 4],
                [2, 2, 2, 10],
                [4, 4, 8, 0]
        ]

DDT_S1 = [
                [16, 0, 0, 0],
                [2, 8, 2, 4],
                [0, 6, 4, 6],
                [4, 2, 8, 2],
                [2, 0, 10, 4],
                [2, 4, 2, 8],
                [0, 10, 0, 6],
                [8, 2, 4, 2],
                [4, 6, 0, 6],
                [8, 2, 4, 2],
                [2, 0, 10, 4],
                [0, 6, 4, 6],
                [6, 0, 6, 4],
                [6, 0, 6, 4],
                [11, 3, 2, 0],
                [2, 8, 2, 4]
        ]

Delta_X0 = ['0', '0', '1', '0']
Delta_Y0 = ['1', '0']

Delta_X1 = ['0', '1', '0', '0']
Delta_Y1 = ['1', '0']

Delta_U = ['0', '0', '0', '0', '0', '1', '0', '0']
Delta_V = ['0', '0', '0', '0', '0', '1', '0', '0']

print('Assuming Round Key used for encryption is 1001001001:')

keys = {}

for i in range(256):   #2^8 = 256 where KEY_SIZE = 8
    keys[i] = 0

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

for count in range(256):
    pt = format(count, '#010b')[2:]
    pt = [x for x in pt]
    pt_dash = []
    
    for i in range(8):
        pt_dash.append(str(int(pt[i]) ^ int(Delta_U[i])))
    
    PT_FileName = 'Temp_PT.txt'
    temp_PT_File = open(PT_FileName, 'w', encoding="utf-8")
    temp_PT_File.write(str(chr(int(''.join(pt),2))) + str(chr(int(''.join(pt_dash),2))))
    temp_PT_File.close()

    CT_FileName = 'Temp_CT.txt'
    temp_CT_File = open(CT_FileName, 'w')
    
    fin = open('Temp_PT.txt', 'r', encoding="utf-8")
    message = fin.read()
    fin.close()
    
    for ch in message:
        a = bin(ord(ch))
        a = a[2:]
        while(len(a) != 8):
            a = '0' + a
        temp_CT_File.write('{}\n'.format(''.join(Encrypt.encrypt(a))))
        
    temp_CT_File.close()
    
    temp_CT_File = open(CT_FileName, 'r')
    ct = temp_CT_File.readline()[:-1]
    ct_dash = temp_CT_File.readline()[:-1]
    
    temp_CT_File.close()
    
    ct = [x for x in ct]
    ct_dash = [x for x in ct_dash]
    
    L2 = []
    R2 = []

    for i in IP1[:4]:
        L2.append(ct[i])

    for i in IP1[4:]:
        R2.append(ct[i])
        
    L2_dash = []
    R2_dash = []

    for i in IP1[:4]:
        L2_dash.append(ct_dash[i])

    for i in IP1[4:]:
        R2_dash.append(ct_dash[i])
        
    R1 = L2
    R1_dash = L2_dash
    
    #Now do exhaustive search on subkey k2
    for k in range(256):
        k2 = format(k, '#010b')[2:]
        k2 = [x for x in k2]
        
        fRk = f(R1, k2)        
        L1 = []
    
        for i in range(4):
            L1.append(str(int(R2[i]) ^ int(fRk[i])))
            
        fRk_dash = f(R1_dash, k2)        
        L1_dash = []
    
        for i in range(4):
            L1_dash.append(str(int(R2_dash[i]) ^ int(fRk_dash[i])))
            
                   
        L1_xor = []
        R1_xor = []
    
        for i in range(4):
            L1_xor.append(str(int(L1[i]) ^ int(L1_dash[i])))
        for i in range(4):
            R1_xor.append(str(int(R1[i]) ^ int(R1_dash[i])))
        
        combined = L1_xor + R1_xor
        
        if combined == Delta_V:
            print('Match found........................ :),', flush = True)
            keys[k] = keys[k] + 1
        else:
            print('Match not found in this case  :(', flush = True)
    # print(count)

maxFreq = 0
bestKey = -1

for i in range(256):
    # print(keys[i])
    if(keys[i] >= maxFreq):
        maxFreq = keys[i]
        bestKey = i

print('Best probable Round key2 is: ')
if bestKey >= 0:
    print(format(bestKey, '#010b')[2:])