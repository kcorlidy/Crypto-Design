key = "1234"
plaintext = "abcd"
strtobin = lambda st: ''.join(format(ord(x), 'b') for x in st)

lens = int(len(plaintext)/2)
L0 = strtobin(plaintext[:lens])
R0 = strtobin(plaintext[lens:])

print("L0:",L0,"\nR0:",R0)
i = 2
key = strtobin(key)

def F(a,key):
	return bin(int(a, 2)+ int(key, 2))[2:]

def encrypt(L0,R0,F):
	L = [L0]
	R = [R0]
	for _ in range(i):	
		L += [R[_]]
		R += ["".join([str(int(a)^int(b)) for a,b in zip(list(L[_]),list(F(R[_],key)))])]
		
	return L[-1],R[-1]

def decrypt(Ln,Rn,F):
	L = [None]*i + [Ln]
	R = [None]*i + [Rn]
	for _ in range(i)[::-1]:
		R[_] = L[_+1]
		L[_] = "".join([str(int(a)^int(b)) for a,b in zip(list(R[_+1]),list(F(L[_+1],key)))])
		
	return L[0],R[0]

Ln,Rn = encrypt(L0,R0,F)
print(Ln,Rn)

L0,R0 = decrypt(Ln,Rn,F)
print(L0,R0)