class DiffieHellmankeyexchange(object):
	
	def __init__(self, p, g):
		self.p = p
		self.g = g

	def pubseed(self, priseed):
		self.priseed = priseed
		return (self.g ** priseed) % self.p

	def s(self, pub):
		return (pub ** self.priseed) % self.p
		
p = 23
g = 5
alice = DiffieHellmankeyexchange(p,g)
bob = DiffieHellmankeyexchange(p,g)
hack = DiffieHellmankeyexchange(p,g)

alice_pub = alice.pubseed(8)
bob_pub = bob.pubseed(14)
hack_pub = hack.pubseed(5)

alice_s = alice.s(bob_pub) # computing s by using Bob_pub
bob_s = bob.s(alice_pub) # computing s by using Alice_pub

hack_s = hack.s(bob_pub) # computing s by using Bob_pub, but Bob_pub not using hack's pubseed
hack_s2 = hack.s(alice_pub) # computing s by using Alice_pub, but Alice_pub not using hack's pubseed

print(alice_s, bob_s, (hack_s, hack_s2))