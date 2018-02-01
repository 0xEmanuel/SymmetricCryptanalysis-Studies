# Status:
# MILP example implemented
# AES with Custom MixColumn Matrix and PermutateState implemented
# to do: combine MILP with AES

##################################### MILP Example

def MILP_example():
  p = MixedIntegerLinearProgram(maximization=False, solver = "GLPK")
  w = p.new_variable(integer=True, nonnegative=True)

  p.add_constraint(w[0] + w[1] + w[2] - 14*w[3] == 0)
  p.add_constraint(w[1] + 2*w[2] - 8*w[3] == 0)
  p.add_constraint(2*w[2] - 3*w[3] == 0)
  p.add_constraint(w[0] - w[1] - w[2] >= 0)
  p.add_constraint(w[3] >= 1)

  p.set_objective(w[3]) #Minimization

  p.show()

  print('Objective Value: {}'.format(p.solve()))

  for i, v in p.get_values(w).iteritems():
      print('w_%s = %s' % (i, int(round(v))))
      
##################################### AES

def MixSingleColumn(column, K, useAESmatrix):  
  M = MatrixSpace(K, 4, 4)
  mat = 0
  if useAESmatrix: # use the normal AES MixColumn Matrix
    mat = M([ 	[K("x"), K("x + 1"), K("1"), K("1")],
		[K("1"), K("x"), K("x + 1"), K("1")],
		[K("1"), K("1"), K("x"), K("x + 1")],
		[K("x + 1"), K("1"), K("1"), K("x")]		
	   ])
  else: # here we can use our own MixColumn Matrix
    mat = M([ 	[K("0"), K("1"), K("1"), K("1")],
		[K("1"), K("0"), K("1"), K("1")],
		[K("1"), K("1"), K("0"), K("1")],
		[K("1"), K("1"), K("1"), K("0")]		
	   ])

  #Matrix multiplication
  res = mat * column


  return res

def MixColumn(state, K, useAESmatrix):
  import copy
  newState = copy.copy(state)
  for i in range(0,4):
    mixedColumn = MixSingleColumn(state[0:4,i], K, useAESmatrix)
    newState[0:4,i] = mixedColumn
  return newState
  
def PermutateState(state, doubleShift):
  if doubleShift:
    state = rgf.shift_rows(state)
    state = rgf.shift_rows(state)
  else:
    state = rgf.shift_rows(state)
  return state
  
def CustomAES(state, K, useAESmatrix):
  rounds = 10
  #ignore key scheduling
  round_key = rgf._hex_to_GF('01010101010101010101010101010101')
  
  for i in range(0,rounds):
    print("Round " , i+1)
    state = rgf.add_round_key(state,round_key)
    state = rgf.sub_bytes(state)
    state = PermutateState(state, false)
    state = MixColumn(state, K, useAESmatrix)
    print(state)
  return state

##################################### TESTS - you can ignore this section
  
def TestMixColumn(K):
  M = MatrixSpace(K, 4, 4)
  initMat = M([ [K("x^7 + x^6 + x^4 + x^2"), K("x^7 + x^6 + x^4 + x^2"), K("x^7 + x^6 + x^4 + x^2"), K("x^7 + x^6 + x^4 + x^2")],
	  [K("x^7 + x^5 + x^4 + x^3 + x^2 + x + 1"), K("x^7 + x^5 + x^4 + x^3 + x^2 + x + 1"), K("x^7 + x^5 + x^4 + x^3 + x^2 + x + 1"), K("x^7 + x^5 + x^4 + x^3 + x^2 + x + 1")],
	  [K("x^6 + x^4 + x^3 + x^2 + 1"), K("x^6 + x^4 + x^3 + x^2 + 1"), K("x^6 + x^4 + x^3 + x^2 + 1"), K("x^6 + x^4 + x^3 + x^2 + 1")],
	  [K("x^5 + x^4"), K("x^5 + x^4"), K("x^5 + x^4"), K("x^5 + x^4")]		
	 ])

  print("InitMat: ")
  print(initMat)

  ##1.MixColumn
  mixed_C = MixColumn(initMat, K, true)
  print("Result mixed_C:")
  print(mixed_C)

  mixed_R = rgf.mix_columns(initMat)
  print("Result mixed_R:")
  print(mixed_R)

  ##2. MixColumn
  mixed_CC = MixColumn(mixed_C, K, true)
  print("Result mixed_CC:")
  print(mixed_CC)

  mixed_RR = rgf.mix_columns(mixed_R)
  print("Result mixed_RR:")
  print(mixed_RR)

  mixed_CR = rgf.mix_columns(mixed_C)
  print("Result mixed_CR:")
  print(mixed_CR)

  mixed_RC = MixColumn(mixed_R,K,true)
  print("Result mixed_RC:")
  print(mixed_RC)
  
  #print("Verify from Example:")
  #print("input:")
  #print(K.fetch_int(0xd4))
  #print(K.fetch_int(0xbf))
  #print(K.fetch_int(0x5d))
  #print(K.fetch_int(0x30))

  #print("result:")
  #print(K.fetch_int(0x04))
  #print(K.fetch_int(0x66))
  #print(K.fetch_int(0x81))
  #print(K.fetch_int(0xe5))
  return
  
##################################### MAIN
from sage.crypto.mq.rijndael_gf import RijndaelGF
rgf = RijndaelGF(4,4)

K = GF(2^8,'x', x^8 + x^4 + x^3 + x + 1 )
M = MatrixSpace(K, 4, 4)


#TestMixColumn(K)

state = rgf._hex_to_GF('11223344556677889912131415161718') # 16 Bytes

CustomAES(state,K,true)




##################################### TRASH - you can ignore this section


#state = rgf._hex_to_GF('d4bf5d30d4bf5d30d4bf5d30d4bf5d30')
#print("State:")
#print(state)

#VEC = MatrixSpace(K, 4, 1)
#vec = VEC([ 	 [K("x^7 + x^6 + x^4 + x^2")],
#		 [K("x^7 + x^5 + x^4 + x^3 + x^2 + x + 1")],
#		 [K("x^6 + x^4 + x^3 + x^2 + 1")],
#		 [K("x^5 + x^4")] 
#	   ])
	   
#res = MixSingleColumn(vec, K, true)
#print(res)

#n is the number of rounds
#r the number of rows in the state array
#c the number of columns in the state array
#e the degree of the underlying field.
#aes = mq.SR(10, 4, 1, 8)
#K = FiniteField(16, "x")
#MS = MatrixSpace(K, 2, 2)
#sage: mat = MS([ [K("x^2 + x + 1"), K("x^3 + x^2 + 1")], [K("x^3"), K("x")] ])
#res = aes.mix_columns(vec)
#print(res)

#sr = mq.SR(10, 4, 1, 8)
#k = sr.base_ring()

#M = MatrixSpace(k,4,1)
#A = M([0xd4, 0xbf, 0x5d, 0x30])

#state = sr.state_array(A)

#k.<x> = GF(2^4)
#t = k.fetch_int(5)
#print(t)


#M=matrix([(1, -2, -1, -1,9), (1, 8, 6, 2,2), (1, 1, -1, 1,4), (-1, 2, -2, -1,4)])
#print(M)
#print(M[0:4,1])
#M[0:4,1] = [[20],[21],[22],[23]]
#print(M)