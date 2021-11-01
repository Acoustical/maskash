package privacy

import (
	"github.com/Acoustical/maskash/crypto"
	"math/big"
)

type Slot interface {
	SlotMode() uint8
	CheckZKs() bool
	Base() Base
	Value() Value
	ZKs() ZKs
	crypto.HashVariable
}

type Base interface {
	BaseMode() uint8
	crypto.HashVariable
}

type Value interface {
	ValueMode() uint8
	Solvable() bool
	Solve(prv *PrivateKey) (*big.Int, error)
	crypto.HashVariable
}

type ZKs interface {
	ZKMode() uint8
	crypto.HashVariable
}