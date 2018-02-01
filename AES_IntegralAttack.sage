# Status:
# AES template implented
# to do: implement integral attack

from sage.crypto.mq.rijndael_gf import RijndaelGF
rgf = RijndaelGF(4, 6)

############################## AES

def AES(state, key_state, full_rounds):
  key_schedule = rgf.expand_key(key_state)

  first_round_key = key_schedule[0]
  state = rgf.add_round_key(state,first_round_key)

  for i in range(0,full_rounds):
    round_key = key_schedule[i+1]
    state = rgf.sub_bytes(state)
    state = rgf.shift_rows(state)
    state = rgf.mix_columns(state)  
    state = rgf.add_round_key(state,round_key)
    print("Round",i+1)
    print(state)

  #final round
  round_key = key_schedule[full_rounds+1]
  state = rgf.sub_bytes(state)
  state = rgf.shift_rows(state)
  state = rgf.add_round_key(state,round_key)

  print("Last round:")
  print(state)
  return state


############################## MAIN

#K = GF(2^8,'x', x^8 + x^4 + x^3 + x + 1 )
#M = MatrixSpace(K, 4, 4)

state = rgf._hex_to_GF('11223344556677889912131415161718') # 16 Bytes
key_state = rgf._hex_to_GF('331D0084B176C3FB59CAA0EDA271B565BB5D9A2D1E4B2892')

AES(state, key_state, 3)
