package zkproofs

import (
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"golang.org/x/crypto/bn256"
	"math/big"
)

type RangePublic struct {
	value *crypto.Commitment
	g, h *crypto.Generator
	g_, h_ []*crypto.Generator
	n uint8
}

func (public *RangePublic) SetPublic(value *crypto.Commitment, g, h *crypto.Generator, g_, h_ []*crypto.Generator, n uint8) (*RangePublic, error){
	if int(n) > (common.Bn256PointBits / common.ByteBits) {
		return nil, errors.NewOverMaxBitError(n, uint8(common.Bn256PointBits / common.ByteBits))
	} else {
		return &RangePublic{value, g, h, g_, h_,n}, nil
	}
}

// public function
func (public *RangePublic) public() {}

type RangePrivate struct {
	*RangePublic
	v, r *big.Int
}

func (private *RangePrivate) SetPrivate(value *crypto.Commitment, g, h *crypto.Generator, g_, h_ []*crypto.Generator, n uint8, v, r *big.Int) (*RangePrivate, error){
	vBitLen := v.BitLen()
	if vBitLen > int(n) {
		return nil, errors.NewOverRangeError(uint8(vBitLen), v)
	}
	var err error
	private.v, private.r = v, r
	private.RangePublic, err = new(RangePublic).SetPublic(value, g, h, g_, h_, n)
	return private, err
}

// private function
func (private *RangePrivate) private() {}

type RangeProof struct {
	a, s, t1, t2 *crypto.Commitment
	left, right []*big.Int
	tau, mu *big.Int
}

func (proof *RangeProof) ProofGen(private *RangePrivate) (*RangeProof, error){
	Len := int(private.n)
	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)
	one_ := new(big.Int).Sub(bn256.Order, one)
	P := bn256.Order

	innerProduct := func(a []*big.Int, b []*big.Int) (*big.Int, error){
		aLen := len(a)
		bLen := len(b)
		if aLen != bLen {
			return nil, errors.NewLengthNotMatchError(aLen, bLen)
		}
		answer := big.NewInt(0)
		for i := 0; i < aLen; i++ {
			ab := new(big.Int).Mul(a[i], b[i])
			answer.Add(answer, ab)
		}
		return answer, nil
	}

	// Random Generates
	mix, err := crypto.RandomZq(2*Len + 4)
	if err != nil {return nil, err}
	sL := mix[:Len]
	sR := mix[Len:2*Len]
	alpha := mix[2*Len]
	rho := mix[2*Len+1]
	tau1 := mix[2*Len+2]
	tau2 := mix[2*Len+3]

	// convert v to aL, aR
	aL := make([]*big.Int, Len)
	aR := make([]*big.Int, Len)
	for i := 0; i < Len; i++ {
		bit := private.v.Bit(i)
		switch bit {
		case 1:
			aL[i] = one
			aR[i] = zero
		case 0:
			aL[i] = zero
			aR[i] = one_
		}
	}

	// calculate A
	hAlpha := new(crypto.Generator).Mul(private.h, alpha)

	gAl, err := new(crypto.Commitment).MultiSet(private.g_, aL)
	if err != nil {return nil, err}

	hAr, err := new(crypto.Commitment).MultiSet(private.h_, aR)
	if err != nil {return nil, err}

	a := new(crypto.Commitment).SetInt(zero).AddGenerator(hAlpha).Add(gAl).Add(hAr)
	proof.a = a

	// calculate S
	hRho := new(crypto.Generator).Mul(private.h, rho)

	gSl, err := new(crypto.Commitment).MultiSet(private.g_, sL)
	if err != nil {return nil, err}

	hSr, err := new(crypto.Commitment).MultiSet(private.h_, sR)
	if err != nil {return nil, err}

	s := new(crypto.Commitment).SetInt(zero).AddGenerator(hRho).Add(gSl).Add(hSr)
	proof.s = s

	// generate y, z by flat-shamir transform
	y := crypto.Hash_(a, s).BigInt()
	y.Mod(y, P)

	z := crypto.Hash_(a, s, y).BigInt()
	z.Mod(z, P)

	// generate function l, r, t
	L := func(x *big.Int) []*big.Int {
		answer := make([]*big.Int, Len)
		for i := 0; i < Len; i++ {
			aLz := new(big.Int).Sub(aL[i], z)
			sLx := new(big.Int).Mul(sL[i], x)
			answer_ := new(big.Int).Add(aLz, sLx)
			answer[i] = answer_.Mod(answer_, P)
		}
		return answer
	}

	R := func(x *big.Int) []*big.Int {
		answer := make([]*big.Int, Len)
		twoExp := big.NewInt(1)
		yExp := big.NewInt(1)
		for i := 0; i < Len; i++ {
			sRx := new(big.Int).Mul(sR[i], x)
			sRx.Add(sRx, z)
			sRx.Add(sRx, aR[i])
			sRx.Mod(sRx, P)
			sRx.Mul(sRx, yExp)
			z2 := new(big.Int).Exp(z, two, P)
			z2.Mul(z2, twoExp)
			yExp.Mul(yExp, y)
			yExp.Mod(yExp, P)
			twoExp.Mul(twoExp, two)
			twoExp.Mod(twoExp, P)
			answer_ := new(big.Int).Add(sRx, z2)
			answer_.Mod(answer_, P)
			answer[i] = answer_
		}
		return answer
	}

	//T := func(x *big.Int) (*big.Int, error) {
	//	return innerProduct(L(x), R(x))
	//}

	// calculate t0, t1, t2
	l0 := L(zero)
	l1 := L(one)
	r0 := R(zero)
	r1 := R(one)

	for i := 0; i < Len; i++ {
		l1[i].Sub(l1[i], l0[i])
		l1[i].Mod(l1[i], P)
		r1[i].Sub(r1[i], r0[i])
		r1[i].Mod(r1[i], P)
	}

	//t0, _ := innerProduct(l0, r0)
	t01, _ := innerProduct(l0, r1)
	t10, _ := innerProduct(l1, r0)
	t1 := new(big.Int).Add(t01, t10)
	t2, _ := innerProduct(l1, r1)

	// calculate T1, T2
	T1 := new(crypto.Commitment).FixedSet(private.g, private.h, t1, tau1)
	T2 := new(crypto.Commitment).FixedSet(private.g, private.h, t2, tau2)

	proof.t1, proof.t2 = T1, T2

	// generate x by flat-shamir transform
	x := crypto.Hash_(a, s, T1, T2, y, z).BigInt()
	x.Mod(x, P)

	// generate l ,r
	l := L(x)
	r := R(x)

	proof.left, proof.right = l, r

	// calculate tau
	x2 := new(big.Int).Exp(x, two, P)
	z2 := new(big.Int).Exp(z, two, P)
	tauX := new(big.Int).Mul(tau1, x)
	tauX2 := new(big.Int).Mul(tau2, x2)
	tau := new(big.Int).Mul(z2, private.r)
	tau.Add(tau, tauX)
	tau.Add(tau, tauX2)

	proof.tau = tau
	return proof, nil
}

func (proof *RangeProof) ProofCheck(public *RangePublic) bool {
	Len := int(public.n)
	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)
	P := new(big.Int).Sub(bn256.Order, one)

	innerProduct := func(a []*big.Int, b []*big.Int) (*big.Int, error){
		aLen := len(a)
		bLen := len(b)
		if aLen != bLen {
			return nil, errors.NewLengthNotMatchError(aLen, bLen)
		}
		answer := big.NewInt(0)
		for i := 0; i < aLen; i++ {
			ab := new(big.Int).Mul(a[i], b[i])
			answer.Add(answer, ab)
		}
		return answer, nil
	}

	// calculate t
	t, _ := innerProduct(proof.left, proof.right)


}
