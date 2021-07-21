package crypto

import (
	"crypto/sha256"
	"math/big"
)

type HashVariable interface {Bytes() []byte}

type Hash [32]byte

func Hash_(args ...HashVariable) Hash {
	hash := sha256.New()
	for i := 0; i < len(args); i++ {
		hash.Write(args[i].Bytes())
	}
	result := hash.Sum(nil)
	var h Hash
	copy(h[:], result)
	return h
}

func (h Hash) Cmp(h0 Hash) bool {return h == h0}

func (h Hash) Bytes() []byte {return h[:]}

func (h Hash) BigInt() *big.Int {return new(big.Int).SetBytes(h[:])}
