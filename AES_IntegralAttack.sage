# Status:
# AES template implented
# to do: implement integral attack


#activatedBytes = ['1a', '68', '8b', 'c1', 'c7', 'c2', '12', 'be', 'cd', '8f', 'd1', 'd4', 'a8', 'a8', '1b', '8d', '8d', 'd6', 'b0', 'e2', 'dd', 'b7', '7e', 'e3', '58', 'e3', 'e0', '9c', '90', '31', 'a3', '23', '91', '89', '62', '5a', '6d', '4f', 'b7', 'f8', 'b5', '7c', 'c9', '96', '6a', '4a', '80', 'd7', 'cb', '09', 'b2', 'ba', 'c4', '12', '66', '51', 'dc', 'f2', '3e', '64', '04', 'c8', '47', '72', 'b7', '40', 'f9', '1e', 'f8', 'eb', 'fe', '6f', '7e', 'ca', 'c8', '56', '4e', 'b8', 'd6', 'c0', 'a0', 'ef', '92', '9a', 'ad', '06', 'b1', 'e5', '9e', '28', '2c', 'd5', '46', '65', 'ad', 'b3', '7d', 'd2', '52', '0e', '7a', '45', '98', 'bb', 'db', '08', '57', '8b', '7c', '17', '18', '09', '35', 'bf', '35', '00', '57', '68', 'bd', '65', 'c2', '7d', '90', 'd8', 'f5', '0e', '34', '07', 'fe', 'c6', '44', 'f3', '1c', '14', '2b', '63', 'da', '8a', 'd4', 'a7', '19', 'a4', 'a5', '68', '71', '6a', 'f5', '69', 'de', '03', '7f', '88', 'df', '41', '2a', '34', '16', 'b9', '08', '59', 'ba', 'b4', '51', '8e', '90', '78', '54', '80', 'd1', '4b', 'f7', '49', '41', '33', '85', '02', '7b', 'e7', '04', '00', '6b', 'c9', '09', 'ca', 'df', '01', '32', '71', '78', '60', '8c', 'd1', '82', '11', 'e7', '07', 'a6', '6f', 'da', '99', '47', '25', '49', '21', '76', '47', 'c8', 'f7', 'e7', '70', 'a6', '7f', 'f4', 'b8', 'ef', 'cd', 'c5', '60', '73', '28', '5f', '59', 'f0', '34', '74', 'e4', 'e5', '99', '38', '39', '15', '7a', '98', 'c1', '62', '78', 'f1', 'a7', '8f', '9d', '6a', '33', 'f2', 'c8', 'fc', '94', '42', '6f', '00', '3c', 'fa', '1c', '96', '0c', '0d', 'e1', 'dc', '69', '1d', '64', '09', '01', 'cf', '85', '79', '40', 'b2', '83', 'f4', '48', '6e', '12', '55', '0d', '82', 'a1', 'cc', 'a1', 'e8', 'a2', '43', '19', 'ff', '1b', '28', '27', 'b4', 'b4', '46', '83', 'c1', '87', '19', 'dc', '3e', '48', '97', '21', 'd6', '68', '31', 'a2', '4f', 'fe', '5a', 'a9', '64', 'b1', 'aa', 'c7', 'a0', '3d', 'f5', 'e0', 'ac', 'e0', 'ee', '2b', '0a', 'f9', '82', '53', 'f6', 'e6', '02', 'd9', '49', '37', '18', '82', '1f', 'ac', 'fd', '13', 'cd', '49', 'b3', 'ed', '54', 'df', '10', 'e2', '9a', '5c', '3a', '95', '63', '92', 'dc', '20', 'c7', '33', 'aa', 'a3', '5b', '45', '2a', 'b1', 'bc', '22', 'fa', '6d', '53', '30', '3f', 'f2', 'f1', '6e', '93', '23', '7b', 'f3', '94', '73', '55', 'd9', '5d', 'ec', '5a', '50', '41', 'd5', '31', '50', '5d', 'af', 'ec', 'e9', '0b', '3f', '0c', 'd0', 'fb', '52', '37', '2b', 'ce', '3a', '2b', '1b', '72', 'd4', '36', '3d', '93', '86', 'bf', 'a3', '48', '93', '8b', '74', '08', '28', '2b', 'ce', 'fc', '5f', 'b2', '51', '97', '3c', '60', 'c0', '58', '78', '73', '32', '27', '4d', 'ea', 'bd', '93', '94', '2b', 'f3', '2d', '27', 'e3', '15', '71', '5c', 'a3', '3f', '3f', 'dd', '56', 'cf', '38', 'ab', '8b', '4d', '39', '15', '85', 'd8', '43', '03', '9e', 'c4', '0f', 'b0', '3a', '2c', '00', '18', '76', '0a', '75', '16', 'f6', '54', '77', 'ec', 'b6', 'ab', '1d', 'be', '70', '73', '24', '5b', '05', '19', '84', '94', '9e', '21', '8c', '47', '6c', 'ae', '8c', 'ff', '9e', 'bc', 'fd', 'e4', 'd3', 'fb', '22', 'c3', '6b', '97', 'af', 'c5', 'd1', 'ec', 'b0', 'dd', '40', '25', 'c1', '0b', '61', '83', '2a', 'e6', '05', '91', '2e', 'b5', '3b', 'e8', '62', '20', '42', 'ab', '44', '01', '87', 'a1', '53', '04', '9f', '9a', 'b2', '06', 'e9', '31', 'a9', '8a', 'ab', '0f', 'db', '68', 'b2', '59', '96', '39', '13', '3d', 'fd', '9f', 'aa', '7b', '75', '37', 'd2', '46', '6b', '14', 'd8', 'b3', '61', 'f2', '8b', 'b5', '86', '9e', '3d', '79', '30', '4f', '24', 'df', '9d', '8b', 'e1', '8e', '05', '2e', 'de', '0d', '3e', '84', '89', '68', '57', '81', 'e4', '03', 'c1', 'ed', '50', '91', 'f7', 'e2', '1c', '61', '99', 'f0', '15', 'dd', 'ae', '5e', 'ae', 'e4', '19', '05', 'e1', '88', 'ab', 'f3', '8f', 'ea', '22', '91', '2f', '1d', '2e', 'fc', '4c', '8b', 'a5', '3b', '12', 'ac', '0e', '0a', '6c', '97', '94', '5e', '87', 'fa', 'b4', '36', '2a', '80', 'b6', '29', '2e', '55', 'a3', '55', 'd4', '21', '4e', '69', '38', '92', 'a9', '99', 'bb', 'f8', 'a1', 'aa', '74', 'ab', '22', '0a', 'bd', 'd7', '2b', 'a8', '2d', '9c', '8b', '00', 'f1', '6f', '4b', '4a', '9a', 'f6', 'b3', 'ff', 'fb', '29', 'd1', '67', '26', 'f9', '9b', '1f', '2d', '70', '95', '8f', '81', '2f', '49', '17', 'cc', '32', 'ee', '67', '19', '29', '66', '38', 'ed', '9d', 'f4', '45', 'eb', '19', 'a0', 'ec', 'c9', 'bd', 'c3', 'd4', '1e', 'd3', 'c5', '90', 'f7', 'f9', 'db', '5e', '2c', 'cd', '56', 'c9', '77', 'c6', 'fa', 'e8', '1a', '61', '10', 'b8', 'fe', 'f4', '52', '27', 'd0', 'd7', 'de', 'bf', '27', 'cf', 'b9', '9b', '3a', '6f', '7c', 'bf', '26', 'c2', '30', '4c', '65', '2d', '88', 'a4', 'aa', '8a', 'cb', 'c3', 'e6', '30', 'ba', '11', '28', '36']


############################## GLOBALS

from sage.crypto.mq.rijndael_gf import RijndaelGF
rgf = RijndaelGF(4, 4)


preparedInputList = []

activatedBytes = []
states = []

############################## AES

def createInputList(): 
  passiveBytes = '010203040506070809101112131415' # 15 Bytes
  for i in range(0,256):
    activeByte = str(hex(i))[2:4].zfill(2) # zerofilled hexstring 00...ff
    preparedInput = activeByte + passiveBytes
    preparedInputList.append(preparedInput)
    #print(preparedInput)
    

def AES(state, key_state, full_rounds, collectActiveBytes):
  key_schedule = rgf.expand_key(key_state)

  print "0. Round"

  first_round_key = key_schedule[0]
  print "Round Key: ", rgf._GF_to_hex(first_round_key)
  
  state = rgf.add_round_key(state,first_round_key)
  print "After AddRoundKey: ", rgf._GF_to_hex(state)

  for i in range(0,full_rounds):
    print i+1,". Round"
    round_key = key_schedule[i+1]
    print "Round Key: ", rgf._GF_to_hex(round_key)
    
    state = rgf.sub_bytes(state)
    print "After SubBytes: ", rgf._GF_to_hex(state)
    
    state = rgf.shift_rows(state)
    print "After ShitRows: ", rgf._GF_to_hex(state)
    
    state = rgf.mix_columns(state)  
    print "After MixColumn: ", rgf._GF_to_hex(state)
    
    state = rgf.add_round_key(state,round_key)
    print "After AddRoundKey: ", rgf._GF_to_hex(state)
    

  if collectActiveBytes:
    activatedBytes.append(rgf._GF_to_hex(state[0,0]))
    states.append(rgf._GF_to_hex(state))
    
  print full_rounds+1,". Round (Final):"  
  #final round
  round_key = key_schedule[full_rounds+1]
  print "Round Key: ", rgf._GF_to_hex(round_key)
  
  state = rgf.sub_bytes(state)
  print "After SubBytes: ", rgf._GF_to_hex(state)
  
  state = rgf.shift_rows(state)
  print "After ShitRows: ", rgf._GF_to_hex(state)
  
  state = rgf.add_round_key(state,round_key)
  print "After AddRoundKey: ", rgf._GF_to_hex(state)

  return state

def checkBalanceProperty():
  balance = 0
  #for activeByteStr in activatedBytes:
  #  activeByte = int(activeByteStr, 16)
  #  #print("activeByte: ", activeByte)
  #  balance = balance ^^ activeByte
  #  print("balance: ", balance)
  
  for stateStr in states:
    stateInt = int(stateStr, 16)
    print "stateInt: ", hex(stateInt)
    balance = balance ^^ stateInt
    print "balance: ", hex(balance)
    
  print("final balance: ", balance)
    
def IntegralAttak():
  key_state = rgf._hex_to_GF('2b7e151628aed2a6abf7158809cf4f3c')
  createInputList()
  for preparedInput in preparedInputList:
    print(preparedInput)
    AES(rgf._hex_to_GF(preparedInput), key_state, 3, true)

  #print(activatedBytes)
  checkBalanceProperty()

  
############################## MAIN

#K = GF(2^8,'x', x^8 + x^4 + x^3 + x + 1 )
#M = MatrixSpace(K, 4, 4)

state = rgf._hex_to_GF('3243f6a8885a308d313198a2e0370734') # 16 Bytes
key_state = rgf._hex_to_GF('2b7e151628aed2a6abf7158809cf4f3c') # 16 Bytes
#AES(state, key_state, 3, false)

IntegralAttak()

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

  