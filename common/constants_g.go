package common

import (
	"github.com/Acoustical/maskash/crypto"
	"math/big"
)

var G = new(crypto.Generator).Init(big.NewInt(1))
