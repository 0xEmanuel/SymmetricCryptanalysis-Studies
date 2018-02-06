#i=0
#j=0
#r=0

ROUNDS = 10 # /* number of rounds */
nxt = 0 # /* next unused state variable index */
dummy = 0 # /* next unused dummy variable index */

filename = 'MILP-AES-With-'+str(ROUNDS)+'-Rounds.sage'

f = open(filename,'w')
f.write("p = MixedIntegerLinearProgram(maximization=False, solver=\"GLPK\")"+'\n')
f.write("x = p.new_variable(binary=True)"+'\n')
f.write("d = p.new_variable(binary=True)"+'\n')


def ShiftRows(a): #a[4][4]
  tmp = [0,0,0,0]
  for i in range(1,4): #(i=1; i < 4; i++)
    for j in range(0,4): #(j = 0; j < 4; j++) 
      tmp[j] = a[i][(j + i) % 4]
    for j in range(0,4): #(j = 0; j < 4; j++)
      a[i][j] = tmp[j]

#BRANCH_NUMBER = 5
BRANCH_NUMBER = 4

def MixColumn(a):
  global nxt, dummy
  for j in range(0,4):
    f.write("p.add_constraint(")
    for i in range(0,4):
      f.write("x[" + str(a[i][j]) + "] + ")
    for i in range(0,3): 
      f.write("x[" + str(nxt+i) + "] + ")
      
    f.write("x[" + str(nxt+3) + "] - "+str(BRANCH_NUMBER)+"*d[" + str(dummy) + "] >= 0)" +'\n')
    
    
    #additional constraint because non-optimal branch number
    f.write("p.add_constraint(")
    for i in range(3):
      f.write("x["+str(nxt+i)+"] + ")
    f.write("x["+str(nxt+3)+"] -d["+str(dummy)+"] >= 0)" + '\n')

    #additional constraint because non-optimal branch number
    f.write("p.add_constraint(")
    for i in range(3):
      f.write("x["+str(a[i][j])+""+"] + ")
    f.write("x["+str(a[3][j])+"] -d["+str(dummy)+"] >= 0)" + '\n')
    
    
    for i in range(0,4):
      f.write("p.add_constraint(")
      f.write("d[" + str(dummy) + "] - x[" + str(a[i][j]) + "] >= 0)" +'\n')
    
    
    for i in range(0,4):
      f.write("p.add_constraint(")
      a[i][j]=nxt
      f.write("d[" + str(dummy) + "] - x[" + str(a[i][j]) + "] >= 0)" +'\n') # a[i][j]=next++
      nxt = nxt + 1
    dummy = dummy + 1
    
    


#######################

a = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]  #a[4][4]; /* the bytes of the AES state */

for i in range(0,4):
  for j in range(0,4):
    a[i][j] = nxt # /* initialize variable indices */
    nxt = nxt + 1
    
#print  "Minimize\n", # /* print objective function */

f.write("p.set_objective(" ) 
for i in range(0, ROUNDS*16-1): #(i = 0; i < ROUNDS*16-1; i++)
  f.write("x["+str(i)+"] + ")
f.write("x[" + str(ROUNDS*16-1) + "])" + '\n' ) 

#print "Subject To\n", # /* round function constraints */
for r in range(0, ROUNDS): #(r = 0; r<ROUNDS; r++)
  ShiftRows(a)
  ShiftRows(a)
  MixColumn(a)

#/* at least one S-box must be active */
f.write("p.add_constraint(")
for i in range(0, ROUNDS*16-1): #(i = 0; i < ROUNDS*16-1; i++)
  f.write( "x[" + str(i) + "] + ")
f.write( "x[" + str(ROUNDS*16-1) + "] >= 1)" + '\n')


f.write('\n')
f.write("solution=p.solve()"+'\n')
f.write("print \"Minimal number of S-boxes:\", solution"+'\n')
f.close()
execfile(filename)

#print "Binary\n", # /* binary constraints */
#for i in range(0,16): #(i = 0; i < 16; i++) 
#  print "x" + str(i) +"\n",
#for i in range(0,dummy): #(i = 0; i < dummy; i++) 
#  print "d" + str(i) +"\n",
#print "End\n"

