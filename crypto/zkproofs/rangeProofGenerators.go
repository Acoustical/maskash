package zkproofs

import (
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"math/big"
)

var RangeG, RangeH = RangeProofGenerators(common.RangeProofShortBits)

func RangeProofGenerators(n int) (g_, h_ []*crypto.Generator) {
	g_ = make([]*crypto.Generator, n)
	h_ = make([]*crypto.Generator, n)
	for i := 0; i < 2*n; i++ {
		k := crypto.Hash_(big.NewInt(int64(i))).BigInt()
		if i < n {
			g_[i] = new(crypto.Generator).Init(k)
		} else {
			h_[i-n] = new(crypto.Generator).Init(k)
		}
	}
	return
}
