package privacy

import (
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"math/big"
)

type PrivateKey struct {*big.Int}

func NewRandomPrivateKey() *PrivateKey {
	key, _ := crypto.RandomZq(1)
	k := key[0]
	return &PrivateKey{k}
}

func NewHashPrivateKey(v... crypto.HashVariable) *PrivateKey {
	if len(v) == 0 {return NewRandomPrivateKey()}
	key := crypto.Hash_(v...).BigInt()
	return &PrivateKey{key}
}

func (prv PrivateKey) GenSecretBase() *SecretBase {
	h := new(crypto.Generator).Init(prv.Int)
	return &SecretBase{h}
}

func (prv PrivateKey) GenPlaintextBase() *PlaintextBase {
	return prv.GenSecretBase().GenPlaintextBase()
}

func (prv PrivateKey) GenAnonymousBase() *AnonymousBase {
	return prv.GenSecretBase().GenAnonymousBase()
}

func (base *SecretBase) GenPlaintextBase() *PlaintextBase {
	addr := crypto.NewAddress(base.h)
	return &PlaintextBase{addr}
}

func (base *SecretBase) GenAnonymousBase() *AnonymousBase {
	rl, _ := crypto.RandomZq(1)
	r := rl[0]

	g := new(crypto.Generator).Init(r)
	h := new(crypto.Generator).Mul(base.h, r)

	return &AnonymousBase{g,h}
}

func (prv *PrivateKey) Solve(c, d *crypto.Commitment) (*big.Int, error) {
	gv := new(crypto.Commitment).Mul(d, prv.Int)
	gv.Neg()
	gv.AddBy(c)

	one := big.NewInt(1)
	max := big.NewInt(int64(common.MaxShortValue))
	for i := big.NewInt(0); i.Cmp(max) < 0; i.Add(i, one) {
		gi := new(crypto.Commitment).SetInt(i)
		if gi.Cmp(gv) {
			return i, nil
		}
	}
	return nil, errors.NewCannotFindValueError()
}