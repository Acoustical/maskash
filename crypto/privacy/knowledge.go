package privacy

import (
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"golang.org/x/crypto/bn256"
	"math/big"
)

type Knowledge struct {
	v, r *big.Int
	solvable bool
}

func (k *Knowledge) Init(v *big.Int, solvable bool) (*Knowledge, error) {
	if v.Cmp(bn256.Order) == 1 {
		return nil, errors.NewValueRunOffError(v)
	} else {
		rs, err := crypto.RandomZq(1)
		if err != nil {return nil, err} else {return &Knowledge{v, rs[0], solvable}, nil}
	}
}

func GenValueByKnowledge(Owner Base, k *Knowledge, solvable bool) (v Value) {
	switch ob := Owner.(type) {
	case *PlaintextBase:
		v = &PlaintextValue{k.v}
	case *SecretBase:
		c1 := new(crypto.Commitment).FixedSet(common.G, ob.h, k.v, k.r)
		if solvable {
			c2 := new(crypto.Commitment).SetInt(k.r)
			v = &SecretValue{c1, c2}
		} else {
			v = &SecretValue{c1, nil}
		}
	case *AnonymousBase:
		c1 := new(crypto.Commitment).FixedSet(ob.g, ob.h, k.v, k.r)
		if solvable {
			c2 := new(crypto.Commitment).SetIntByGenerator(ob.g, k.r)
			v = &SecretValue{c1, c2}
		} else {
			v = &SecretValue{c1, nil}
		}
	}
	return
}

