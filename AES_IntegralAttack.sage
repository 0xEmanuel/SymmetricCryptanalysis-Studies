# Status:
# AES template implented
# to do: implement integral attack

############################## GLOBALS
VERBOSE = false

from sage.crypto.mq.rijndael_gf import RijndaelGF
rgf = RijndaelGF(4, 4)


pairs = []

activatedBytes = []
states = []

thirdRoundStates = []

afterLastSubBytesStates = []
afterLastShiftRowsStates = []
afterLastAddRoundKeyStates = []

############################## AES

def _print(text):
  if VERBOSE:
    print text 
    

def AES(state, key_state, full_rounds, collectStates): # collectStates=false -> AES-Only / true -> collect States for IntegralAttack
  key_schedule = rgf.expand_key(key_state)

  _print("0. Round")

  first_round_key = key_schedule[0]
  _print("Round Key: " + rgf._GF_to_hex(first_round_key) )
  
  state = rgf.add_round_key(state,first_round_key)
  _print("After AddRoundKey: " + rgf._GF_to_hex(state) )

  for i in range(0,full_rounds):
    _print( str(i+1) + ". Round" )
    round_key = key_schedule[i+1]
    _print("Round Key: " + rgf._GF_to_hex(round_key) )
    
    state = rgf.sub_bytes(state)
    _print("After SubBytes: " + rgf._GF_to_hex(state) )
    
    state = rgf.shift_rows(state)
    _print("After ShitRows: " + rgf._GF_to_hex(state) )
    
    state = rgf.mix_columns(state)  
    _print("After MixColumn: " + rgf._GF_to_hex(state) )
    
    state = rgf.add_round_key(state,round_key)
    _print("After AddRoundKey: " + rgf._GF_to_hex(state) )
    

  if collectStates:
    activatedBytes.append(rgf._GF_to_hex(state[0,0]))
    states.append(rgf._GF_to_hex(state))
    
  _print(str(full_rounds+1) + ". Round (Final):")
  #final round
  round_key = key_schedule[full_rounds+1]
  _print("Round Key: " + rgf._GF_to_hex(round_key) )
  
  state = rgf.sub_bytes(state)
  _print("After SubBytes: " + rgf._GF_to_hex(state) )
  if collectStates:
    afterLastSubBytesStates.append(rgf._GF_to_hex(state))
  
  state = rgf.shift_rows(state)
  _print("After ShitRows: " + rgf._GF_to_hex(state) )
  if collectStates:
    afterLastShiftRowsStates.append(rgf._GF_to_hex(state))
  
  state = rgf.add_round_key(state,round_key)
  _print("After AddRoundKey: " + rgf._GF_to_hex(state) )
  if collectStates:
    afterLastAddRoundKeyStates.append(rgf._GF_to_hex(state))

  return state

def StateSum(stateList):
  stateSum = 0
  #for activeByteStr in activatedBytes:
  #  activeByte = int(activeByteStr, 16)
  #  #print("activeByte: ", activeByte)
  #  balance = balance ^^ activeByte
  #  print("balance: ", balance)
  
  for stateStr in stateList:
    stateInt = int(stateStr, 16)
    print "stateInt: ", hex(stateInt)
    stateSum = stateSum ^^ stateInt
    print "intermediate stateSum: ", hex(stateSum)
    
  print("stateSum: ", str(hex(stateSum)).zfill(32) )
  return stateSum 
 
def IntegralAttack():
  print "Run IntegralAttack ..."
  #key_state = rgf._hex_to_GF('11223344556677889910111213141516') # 2b7e151628aed2a6abf7158809cf4f3c
  #createInputList()
  #for preparedInput in preparedInputList:
  #  print(preparedInput)
  #  AES(rgf._hex_to_GF(preparedInput), key_state, 3, true)

  #print(activatedBytes)
  #balanced = StateSum(states)
  #print "balanced: ", hex(balanced)

  #afterLastSubBytesStateSum = StateSum(afterLastSubBytesStates)
  #print "afterLastSubBytesStateSum: ", hex(afterLastSubBytesStateSum)
  
  #afterLastShiftRowsStateSum = StateSum(afterLastShiftRowsStates)
  #print "afterLastShiftRowsStateSum: ", hex(afterLastShiftRowsStateSum)
  
  #afterLastAddRoundKeyStateSum = StateSum(afterLastAddRoundKeyStates)
  #print "afterLastAddRoundKeyStates: ", hex(afterLastAddRoundKeyStateSum)
  
  for pair in pairs:
    cipher = pair[1]
    
    #'ef44a541a8525b7fb671253bdb0bad00'
    
    #'ef111111111111111111111111111111'
    #'004f6a95d5768832578d1e338f8fe801'
    
    #'11441111111111111111111111111111'
    ####
    
    #'4b87a9fe0b279e5130849f791e36a727'
    
    # '4b871111111111111111111111111111'
    # '0062e33c1c0064dd5089a069293d368e'
    
    state = rgf._hex_to_GF(cipher)
    
    state = rgf.add_round_key(state,rgf._hex_to_GF('ef44a511111111111111111111111111'))
    print "After InverseAddRoundKey: ", rgf._GF_to_hex(state)

    #Its easier to detect the 00-byte if we just skip the InverseShiftRows, so the bytes keep the same index
    #state = rgf.shift_rows(state, algorithm='decrypt')
    #print "After InverseShitRows: ", rgf._GF_to_hex(state)

    state = rgf.sub_bytes(state, algorithm='decrypt')
    print "After InverseSubBytes: ", rgf._GF_to_hex(state)
    
    thirdRoundStates.append(rgf._GF_to_hex(state))
  
  StateSum(thirdRoundStates)
  
  #template = '01020304050607080910111213141516'
  #for i in range(0,1,2): #len(template) iterate over the bytes in the template  
  #  for j in range(0,256): #create random byte      
  #    activeByte = str(hex(j))[2:4].zfill(2) # zerofilled hexstring 00...ff
  #    roundkeyGuess = template[0:i] + activeByte + template[i+2:len(template)] 
  

  
  
def createCpaPairs(): 
  template = '01020304050607080910111213141516' # 16 Bytes
	      
  
  key_state = rgf._hex_to_GF('2b7e151628aed2a6abf7158809cf4f3c') # 16 Bytes #  2b7e151628aed2a6abf7158809cf4f3c   fff22ff4ff5667ff8991ff112131ff16
  #4th roundkey= 4b87a9fe0b279e5130849f791e36a727
  
  #0,1
  #2,3
  #4,5
  for i in range(4,5,2): #len(template) iterate over the bytes in the template  
    for j in range(0,256): #create random byte      
      activeByte = str(hex(j))[2:4].zfill(2) # zerofilled hexstring 00...ff
      preparedPlaintext = template[0:i] + activeByte + template[i+2:len(template)] 
      cipherText = rgf._GF_to_hex( AES(rgf._hex_to_GF(preparedPlaintext), key_state, 3, true) )
      
      pair = []
      pair.append(preparedPlaintext)
      pair.append(cipherText)
      
      pairs.append(pair)
      
      print(preparedPlaintext)
      #print(cipherText)
      
        
      
############################## MAIN

#K = GF(2^8,'x', x^8 + x^4 + x^3 + x + 1 )
#M = MatrixSpace(K, 4, 4)

#state = rgf._hex_to_GF('3243f6a8885a308d313198a2e0370734') # 16 Bytes
#key_state = rgf._hex_to_GF('2b7e151628aed2a6abf7158809cf4f3c') # 16 Bytes

#state = AES(state, key_state, 3, false)


  
  
createCpaPairs()
IntegralAttack()


#IntegralAttack()


######## OUTPUT
#0. Round                                                                                                                                                                                                                      
#Round Key:  2b7e151628aed2a6abf7158809cf4f3c                                                                                                                                                                                  
#After AddRoundKey:  193de3bea0f4e22b9ac68d2ae9f84808                                                                                                                                                                          
#1 . Round                                                                                                                                                                                                                     
#Round Key:  a0fafe1788542cb123a339392a6c7605
#After SubBytes:  d42711aee0bf98f1b8b45de51e415230
#After ShitRows:  d4bf5d30e0b452aeb84111f11e2798e5
#After MixColumn:  046681e5e0cb199a48f8d37a2806264c
#After AddRoundKey:  a49c7ff2689f352b6b5bea43026a5049
#2 . Round
#Round Key:  f2c295f27a96b9435935807a7359f67f
#After SubBytes:  49ded28945db96f17f39871a7702533b
#After ShitRows:  49db873b453953897f02d2f177de961a
#After MixColumn:  584dcaf11b4b5aacdbe7caa81b6bb0e5
#After AddRoundKey:  aa8f5f0361dde3ef82d24ad26832469a
#3 . Round
#Round Key:  3d80477d4716fe3e1e237e446d7a883b
#After SubBytes:  ac73cf7befc111df13b5d6b545235ab8
#After ShitRows:  acc1d6b8efb55a7b1323cfdf457311b5
#After MixColumn:  75ec0993200b633353c0cf7cbb25d0dc
#After AddRoundKey:  486c4eee671d9d0d4de3b138d65f58e7
#4 . Round (Final):
#Round Key:  ef44a541a8525b7fb671253bdb0bad00
#After SubBytes:  52502f2885a45ed7e311c807f6cf6a94
#After ShitRows:  52a4c89485116a28e3cf2fd7f6505e07
#After AddRoundKey:  bde06dd52d43315755be0aec2d5bf307

########################### TRASH

#afterLastSubBytesStateSum:  8a53233ab66b50406804ced52e2b4505
#afterLastShiftRowsStateSum:  8a6bce05b604453a682b23402e5350d5
#afterLastAddRoundKeyStates:  8a6bce05b604453a682b23402e5350d5


#state = rgf._hex_to_GF('8a6bce05b604453a682b23402e5350d5')
#state = rgf.add_round_key(state,rgf._hex_to_GF('ef44a541a8525b7fb671253bdb0bad00')) 
#print "After InverseAddRoundKey: ", rgf._GF_to_hex(state)

#state = rgf.shift_rows(state, algorithm='decrypt')
#print "After InverseShitRows: ", rgf._GF_to_hex(state)

#state = rgf.sub_bytes(state, algorithm='decrypt')
#print "After InverseSubBytes: ", rgf._GF_to_hex(state)