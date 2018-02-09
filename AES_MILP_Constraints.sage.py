# -*- coding: utf-8 -*-

# This file was *autogenerated* from the file AES_MILP_Constraints.sage
from sage.all_cmdline import *   # import sage library

_sage_const_3 = Integer(3); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0); _sage_const_4 = Integer(4); _sage_const_8 = Integer(8); _sage_const_10 = Integer(10); _sage_const_16 = Integer(16)

#Example: 16 S-Sboxes * 10 Rounds = 160 variables

ROUNDS = _sage_const_10  # /* number of rounds */
nxt = _sage_const_0  # /* next unused state variable index */
dummy = _sage_const_0  # /* next unused dummy variable index */

#Singleton-Bound Variables: d<= n-k+1  ... d (BRANCH_NUMBER)
#BRANCH_NUMBER = 5 
BRANCH_NUMBER = _sage_const_4 
LENGTH_n = _sage_const_8 
DIMENSION_k = _sage_const_4 



filename = 'MILP-AES-With-'+str(ROUNDS)+'-Rounds.sage'

f = open(filename,'w')
f.write("p = MixedIntegerLinearProgram(maximization=False, solver=\"GLPK\")"+'\n')
f.write("x = p.new_variable(binary=True)"+'\n')
f.write("d = p.new_variable(binary=True)"+'\n')


def ShiftRows(a): #a[4][4]
  tmp = [_sage_const_0 ,_sage_const_0 ,_sage_const_0 ,_sage_const_0 ]
  for i in range(_sage_const_1 ,_sage_const_4 ): #no shifting for first row , i: rows index
    for j in range(_sage_const_0 ,_sage_const_4 ): # j: column index
      tmp[j] = a[i][(j + i) % _sage_const_4 ] # i says how much we shift , mod 4 makes sure to continue shifting on the other side
    for j in range(_sage_const_0 ,_sage_const_4 ):
      a[i][j] = tmp[j]
      
  return a


# Branch Number 5:
# x_in[0] + x_in[1] + x_in[2] + x_in[3] + x_out[0] + x_out[1] + x_out[2] + x_out[3] - 5d >= 0

# Branch Number 4:
# x_in[0] + x_in[1] + x_in[2] + x_in[3] + x_out[0] + x_out[1] + x_out[2] + x_out[3] - 4d >= 0
#
# ...Attention:
# x_in[0] = x_in[1] = x_in[2] = x_in[3] = 1 
# x_out[0] = x_out[1] = x_out[2] = x_out[3] = 0
# -> 1+1+1+1+0 = 4 ---> TRUE, BUT IT MAKES NO SENSE TO HAVE THIS: there should be at least one active S-Box!
#
# so we add additional constraints:
# 
# x_in[0] + x_in[1] + x_in[2] + x_in[3] -d >= 0
# x_out[0] + x_out[1] + x_out[2] + x_out[3] -d >= 0

def MixColumn(a):
  global nxt, dummy
  for j in range(_sage_const_0 ,_sage_const_4 ): # iterate over columns
    f.write("p.add_constraint(")
    for i in range(_sage_const_0 ,_sage_const_4 ):
      f.write("x[" + str(a[i][j]) + "] + ")
    for i in range(_sage_const_0 ,_sage_const_3 ): 
      f.write("x[" + str(nxt+i) + "] + ")
      
    f.write("x[" + str(nxt+_sage_const_3 ) + "] - "+str(BRANCH_NUMBER)+"*d[" + str(dummy) + "] >= 0)" +'\n')
    
    if BRANCH_NUMBER < (LENGTH_n - DIMENSION_k + _sage_const_1 ): # Singleton bound: d<= n-k+1 
      #branch number 4 is not optimal
      #here: 4 !<= 8-4+1 ....AES MixColumn Matrix: 5 = 8-4+1 # MixColumn Matrix is MDS Maximum Distance Separable Code. I.e. meets the Singelton bound
      #additional constraint because non-optimal branch number
      f.write("p.add_constraint(")
      for i in range(_sage_const_3 ):
	f.write("x["+str(nxt+i)+"] + ")
      f.write("x["+str(nxt+_sage_const_3 )+"] -d["+str(dummy)+"] >= 0)" + '\n')

      #additional constraint because non-optimal branch number
      f.write("p.add_constraint(")
      for i in range(_sage_const_3 ):
	f.write("x["+str(a[i][j])+""+"] + ")
      f.write("x["+str(a[_sage_const_3 ][j])+"] -d["+str(dummy)+"] >= 0)" + '\n')
    
    
    for i in range(_sage_const_0 ,_sage_const_4 ):
      f.write("p.add_constraint(")
      f.write("d[" + str(dummy) + "] - x[" + str(a[i][j]) + "] >= 0)" +'\n')
    
    
    for i in range(_sage_const_0 ,_sage_const_4 ):
      f.write("p.add_constraint(")
      a[i][j]=nxt
      f.write("d[" + str(dummy) + "] - x[" + str(a[i][j]) + "] >= 0)" +'\n')
      nxt = nxt + _sage_const_1 
    dummy = dummy + _sage_const_1 
    
  return a

#######################

a = [[_sage_const_0 ,_sage_const_0 ,_sage_const_0 ,_sage_const_0 ],[_sage_const_0 ,_sage_const_0 ,_sage_const_0 ,_sage_const_0 ],[_sage_const_0 ,_sage_const_0 ,_sage_const_0 ,_sage_const_0 ],[_sage_const_0 ,_sage_const_0 ,_sage_const_0 ,_sage_const_0 ]]  #a[4][4]; /* the bytes of the AES state */

for i in range(_sage_const_0 ,_sage_const_4 ):
  for j in range(_sage_const_0 ,_sage_const_4 ):
    a[i][j] = nxt # /* initialize variable indices */
    nxt = nxt + _sage_const_1 
    
#print  "Minimize\n", # /* print objective function */

f.write("p.set_objective(" ) 
for i in range(_sage_const_0 , ROUNDS*_sage_const_16 -_sage_const_1 ):
  f.write("x["+str(i)+"] + ")
f.write("x[" + str(ROUNDS*_sage_const_16 -_sage_const_1 ) + "])" + '\n' ) 

#print "Subject To\n", # /* round function constraints */
for r in range(_sage_const_0 , ROUNDS):
  a = ShiftRows(a)
  #a = ShiftRows(a)
  a = MixColumn(a)

#/* at least one S-box must be active */
f.write("p.add_constraint(")
for i in range(_sage_const_0 , ROUNDS*_sage_const_16 -_sage_const_1 ):
  f.write( "x[" + str(i) + "] + ")
f.write( "x[" + str(ROUNDS*_sage_const_16 -_sage_const_1 ) + "] >= 1)" + '\n')


f.write('\n')
f.write("solution=p.solve()"+'\n')
f.write("print \"Minimal number of S-boxes:\", solution"+'\n')
f.close()

execfile(filename)

##
# AES used the wide-trail strategy:
# Theorem:Any differential/linear characteristic over 4 rounds of AES has at least 25 active Sboxes.

####Output:
#
# 10 Rounds
# BranchNumber: 4
##
# PermutateState: ShiftRows()			
# Minimal number of S-boxes: 36.0
#
##1. Round:  1 active Byte 			-> AddKey: " -> SubBytes: " -> ShiftRow: 1 active Byte (if at (0,0) ) 			-> MixColumn: 4 active bytes (0,0),(1,0),(2,0),(3,0)
##2. Round:  4 active Bytes in first column. 	-> AddKey: " -> SubBytes: " -> ShiftRow: 4 active Bytes (each column, 1 active Byte)	-> MixColumn: all Bytes active
#
#
# PermutateState ShiftRows() o ShiftRows()
# Minimal number of S-boxes: 20.0
#
##1. Round: the same
##2. Round:  4 active Bytes in first column. 	-> AddKey: " -> SubBytes: "    -> ShiftRow: 4 active Bytes (each column, 1 active Byte) 
#									--> again ShiftRow: 4 active Bytes at Column0: (0,0),(2,0) and at Column2: (1,2),(4,2) -> MixColumn: only two columns mixed ( 8 bytes active )
#
###############################################
#
# Some Tests
#
# BranchNumber: 5
# PermutateState: ShiftRows()
# Minimal number of S-boxes: 55.0
#
# PermutateState ShiftRows() o ShiftRows()
# Minimal number of S-boxes: 35.0

# 4 Rounds
# BranchNumber: 5
#
# PermutateState: ShiftRows()
# Minimal number of S-boxes: 25.0 # See Theorem
#
# PermutateState ShiftRows() o ShiftRows()
# Minimal number of S-boxes: 15.0
