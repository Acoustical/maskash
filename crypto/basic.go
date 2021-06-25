package crypto

type Address [20]byte

func NewAddress(h *Generator) Address {
	raw := Hash_(h)
	var addr Address
	copy(addr[:], raw[len(raw)-20:])
	return addr
}


