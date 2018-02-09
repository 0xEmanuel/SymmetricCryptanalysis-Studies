
# IntegralAttack over all 16 key bytes of the 4th round key


############################## GLOBALS
VERBOSE = false

from sage.crypto.mq.rijndael_gf import RijndaelGF
rgf = RijndaelGF(4, 4)

key_state_G = rgf._hex_to_GF('2b7e151628aed2a6abf7158809cf4f3c') # 16 Bytes

############################## AES

def _print(text):
  if VERBOSE:
    print text 
    

def AES(state, key_state, full_rounds):
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
    
  ###final round 
  _print(str(full_rounds+1) + ". Round (Final):")
  
  round_key = key_schedule[full_rounds+1]
  _print("Round Key: " + rgf._GF_to_hex(round_key) )
  
  state = rgf.sub_bytes(state)
  _print("After SubBytes: " + rgf._GF_to_hex(state) )
  
  state = rgf.shift_rows(state)
  _print("After ShitRows: " + rgf._GF_to_hex(state) )
  
  state = rgf.add_round_key(state,round_key)
  _print("After AddRoundKey: " + rgf._GF_to_hex(state) )

  return state

def isBalancedByBytePosition(stateSum, bytePosition): # check if the byte at bytePosition is 00
  bytePosition = bytePosition * 2  
  if stateSum[bytePosition:bytePosition+2] == '00':
    return true
  return false

def calcStateXorSum(stateList): ## TODO: Faster if I XOR only the active/relevant byte, probably not much more
  print "Sum up thirdRoundStates ..."
  
  stateSum = 0 
  for stateStr in stateList:
    stateInt = int(stateStr, 16)
    #print "stateInt: ", hex(stateInt)
    stateSum = stateSum ^^ stateInt
    #print "intermediate stateSum: ", hex(stateSum)
    
  print "stateSum: " + '{:032x}'.format(stateSum)
  return '{:032x}'.format(stateSum) #zero filled to 32 chars
 
def createKeyGuessByBytePosition(byteIndex, byteGuess):
  byteIndex = byteIndex * 2

  template = '11111111111111111111111111111111'
  keyGuess = template[0:byteIndex] + '{:02x}'.format(byteGuess) + template[byteIndex+2:len(template)] #    str(hex(byteGuess)).zfill(2)
  return keyGuess
 
def IntegralAttack(keyByteGuessList, plainTextTemplate): # keyByteGuessList is a nested List [[],[],...,[]], with all possible keyBytes (00...ff) or keyByte candidates (from previous IntegralAttack() run) at every bytePosition. 
  print "Run IntegralAttack ..."
  
  allKeyByteCandidates = []
  
  #####
  for activeBytePosition in range(0,16): #iterate over all 16 key bytes. Each iteration we handle one active byte / key byte at fixed position
    print "activeBytePosition: " + str(activeBytePosition)
    cipherTextList = createPairsByBytePosition(activeBytePosition, plainTextTemplate) # '01020304050607080910111213141516'
    
    keyByteGuesses = keyByteGuessList[activeBytePosition]
    ####
    keyByteCandidates = [] # candidates for a single keyByte at one fixed position
    for keyByteGuess in keyByteGuesses: # guess keyByte
      keyGuess = createKeyGuessByBytePosition(activeBytePosition,keyByteGuess)
      print "keyGuess: " + keyGuess
      
      thirdRoundStates = []
      ###
      for cipherText in cipherTextList: #iterate over all cipherTexts. Each ciphertext has only 1 activeByte at a fixed position in this loop       
	state = rgf._hex_to_GF(cipherText)
	state = rgf.add_round_key(state,rgf._hex_to_GF(keyGuess)) # 'ef111111111111111111111111111111'   'ef44a541a8525b7fb671253bdb0bad00'
	#print "After InverseAddRoundKey: ", rgf._GF_to_hex(state)

	#Its easier to detect the 00-byte if we just skip the InverseShiftRows, so the bytes keep the same index
	#state = rgf.shift_rows(state, algorithm='decrypt')
	#print "After InverseShitRows: ", rgf._GF_to_hex(state)

	state = rgf.sub_bytes(state, algorithm='decrypt')
	#print "After InverseSubBytes: ", rgf._GF_to_hex(state)
	
	thirdRoundStates.append(rgf._GF_to_hex(state))
      ###  
      # after calculating all possible (255) third round states for that keyByteGuess, we need calculate the xor-sum of all states. At the index of the keyByteGuess we need to get a 00-Byte in the sum 
      stateSum = calcStateXorSum(thirdRoundStates)
      if( isBalancedByBytePosition(stateSum, activeBytePosition) ): #if state is balanced
	#do not break loop, since we could have false positives (more key byte candidates)      
	keyByteCandidates.append(keyByteGuess)    
	print "added keyByteGuess to keyByteCandidates" 
    #### finished keyByte guesses at one single position
    allKeyByteCandidates.append(keyByteCandidates) # add them to the total list
    print keyByteCandidates
  #####  
  
  return allKeyByteCandidates
  
  
def createPairsByBytePosition(index, template): 
  index = index * 2 # 1 Byte is 2 digits/chars
  #template = '01020304050607080910111213141516' # 16 Bytes	      
  
  cipherTextList = []
  for j in range(0,256): #create random byte      
    activeByte = '{:02x}'.format(j) # zerofilled hexstring 00...ff
    preparedPlaintext = template[0:index] + activeByte + template[index+2:len(template)] 
    cipherText = rgf._GF_to_hex( AES(rgf._hex_to_GF(preparedPlaintext), key_state_G, 3) )
    
    cipherTextList.append(cipherText)
    print(preparedPlaintext)
    #print(cipherText)
      
  return cipherTextList    
 

### For Output

def flatNestedList(list_of_lists):
  flattened = [val for sublist in list_of_lists for val in sublist]
  return flattened

def keyBytesToHexString(keyByteList):
  hexstring = ''
  for keyByte in keyByteList:
    hexstring += '{:02x}'.format(keyByte)
  return hexstring

############################## MAIN

##Init

#create a 16x256 List of guesses, each bytePosition has 256 guesses
guesses = []
for i in range(0,16):
  guesses.append(range(0,255))

##Phase 1 - find keyByte candidates
allKeyByteCandidates = IntegralAttack(guesses, '01020304050607080910111213141516') #try all possible keyBytes
#allKeyByteCandidates = [[152, 197, 239], [68], [165, 183, 204], [65], [161, 168, 216], [82], [91, 195, 237], [127], [47, 182, 241], [113, 134], [37, 115], [59, 122], [219], [11], [129, 173], [0]]

##Phase 2 - check keyByte candidates
keyBytes = IntegralAttack(allKeyByteCandidates, '22222222222222222222222222222222') #tries now only the keyByte candidates on new cipherTexts based on different plainText template
#keyBytes = [[239], [68], [165], [65], [168], [82], [91], [127], [182], [113], [37], [59], [219], [11], [173], [0]]

##Output
print "4th-round key: " + keyBytesToHexString( flatNestedList(keyBytes) )
# 4th-round key: ef44a541a8525b7fb671253bdb0bad00


######## Some Testing stuff - ignore this section

#K = GF(2^8,'x', x^8 + x^4 + x^3 + x + 1 )
#M = MatrixSpace(K, 4, 4)

#state = rgf._hex_to_GF('3243f6a8885a308d313198a2e0370734') # 16 Bytes
#key_state = rgf._hex_to_GF('2b7e151628aed2a6abf7158809cf4f3c') # 16 Bytes

#state = AES(state, key_state, 3)

######## AES OUTPUT
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
