package zkproofs

import (
	"fmt"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"golang.org/x/crypto/bn256"
	"math/big"
	"os"
)

// LinearEquationPublic contains the linear equation public variables
type LinearEquationPublic struct {
	a []*big.Int
	b *big.Int
	y *crypto.Commitment
	g []*crypto.Generator
}

// SetPublic init lep
func (lep *LinearEquationPublic) SetPublic(a []*big.Int, b *big.Int, y *crypto.Commitment, g []*crypto.Generator) (*LinearEquationPublic, error) {
	aLen := len(a)
	gLen := len(g)
	if aLen != gLen {
		return nil, errors.NewLengthNotMatchError(aLen, gLen)
	}
	lep.y = y
	lep.b = b
	lep.a = a
	lep.g = g
	return lep, nil
}

// public function
func (lep *LinearEquationPublic) public() {}

// LinearEquationPrivate contains the linear equation public variables
type LinearEquationPrivate struct {
	LinearEquationPublic
	x []*big.Int
}

// SetPrivate init lep
func (lep *LinearEquationPrivate) SetPrivate(a []*big.Int, b *big.Int, x []*big.Int, y *crypto.Commitment, g []*crypto.Generator) (*LinearEquationPrivate, error) {
	aLen := len(a)
	xLen := len(x)
	if aLen != xLen {
		return nil, errors.NewLengthNotMatchError(aLen, xLen)
	}
	lep.x = x
	_, err := lep.SetPublic(a, b, y, g)
	return lep, err
}

// private function
func (lep *LinearEquationPrivate) private() {}

// LinearEquationProof contains the generated linear equation proof variables
type LinearEquationProof struct {
	s []*big.Int
	t *crypto.Commitment
}

// ProofGen generates linear equation proof
func (proof *LinearEquationProof) ProofGen(private *LinearEquationPrivate) (*LinearEquationProof, error) {
	Len := len(private.a)
	hashVar := make([]crypto.HashVariable, Len+2)
	for i := 0; i < Len; i++ {
		hashVar[i] = private.g[i]
	}
	hashVar[Len] = private.y

	// calculate v
	v := make([]*big.Int, Len)
	ss := make([]bool, Len)
	P1 := new(big.Int).Sub(bn256.Order, big.NewInt(1))
	ssnum := 0
	for i, ai := range private.a {
		if ai.Cmp(big.NewInt(0)) == 0 {
			ss[i] = false
		} else {
			ss[i] = true
			ssnum += 1
		}
	}
	var rbi []*big.Int
	var err error
	if ssnum == 0 {
		rbi, err = crypto.RandomZq(Len)
	} else {
		rbi, err = crypto.RandomZq(Len - 1)
	}
	if err != nil {
		return nil, err
	}
	line := 0
	last := big.NewInt(0)
	for i, ai := range private.a {
		if !ss[i] {
			v[i] = rbi[line]
			line++
		} else {
			if ssnum == 1 {
				Ai := new(big.Int).Set(ai)
				Ai.ModInverse(Ai, P1)
				v[i] = new(big.Int).Mul(last, Ai)
				v[i].Mod(v[i], P1)
				ssnum--
			} else {
				v[i] = rbi[line]
				line++
				ssnum--
				buf := new(big.Int).Mul(ai, v[i])
				last.Sub(last, buf)
				last.Mod(last, P1)
			}
		}
	}

	// calculate t
	proof.t, err = new(crypto.Commitment).MultiSet(private.g, v)
	if err != nil {
		return nil, err
	}

	hashVar[Len+1] = proof.t

	// calculate c
	c := crypto.Hash_(hashVar...).BigInt()

	// calculate s
	proof.s = make([]*big.Int, Len)
	for i := 0; i < Len; i++ {
		cx := new(big.Int).Mul(c, private.x[i])
		cx.Sub(v[i], cx)
		cx.Mod(cx, P1)
		proof.s[i] = cx
	}

	return proof, nil
}

// ProofCheck check weather the linear equation proof holds
func (proof *LinearEquationProof) ProofCheck(public *LinearEquationPublic) bool {
	Len := len(public.a)
	hashVar := make([]crypto.HashVariable, Len+2)
	for i := 0; i < Len; i++ {
		hashVar[i] = public.g[i]
	}
	hashVar[Len] = public.y
	hashVar[Len+1] = proof.t

	// calculate c
	c := crypto.Hash_(hashVar...).BigInt()

	// check t
	t, err := new(crypto.Commitment).MultiSet(public.g, proof.s)
	if err != nil {
		_ = fmt.Errorf("%s", err)
		os.Exit(1)
	}

	yc := new(crypto.Commitment).Mul(public.y, c)
	t.Add(yc)

	if !t.Cmp(proof.t) {
		return false
	}

	// check s
	zero := big.NewInt(0)
	P1 := new(big.Int).Sub(bn256.Order, big.NewInt(1))
	as := new(big.Int).Mul(c, public.b)
	as.Mod(as, P1)
	for i := 0; i < Len; i++ {
		aisi := new(big.Int).Mul(public.a[i], proof.s[i])
		as.Add(as, aisi)
		as.Mod(as, P1)
	}

	if as.Cmp(zero) == 0 {
		return true
	} else {
		return false
	}
}
