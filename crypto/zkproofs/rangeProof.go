package zkproofs

import (
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"golang.org/x/crypto/bn256"
	"math/big"
)

type RangeZK struct {
	*RangeProof
	*RangePrivate
}

func (zk *RangeZK) Init() *RangeZK{
	zk.RangeProof = new(RangeProof)
	zk.RangePrivate = new(RangePrivate)
	zk.RangePublic = new(RangePublic)
	return zk
}

func (zk *RangeZK) Proof() (err error){
	zk.RangeProof, err = new(RangeProof).ProofGen(zk.RangePrivate)
	return
}

func (zk *RangeZK) Check() bool {
	return zk.RangeProof.ProofCheck(zk.RangePublic)
}

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
		public.value, public.g, public.h, public.g_, public.h_, public.n = value, g, h, g_, h_, n
		return public, nil
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
	hAlpha := new(crypto.Generator).Mul(private.h, alpha)		//h^alpha

	gAl, err := new(crypto.Commitment).MultiSet(private.g_, aL)	//g_^aL
	if err != nil {return nil, err}

	hAr, err := new(crypto.Commitment).MultiSet(private.h_, aR)	//h_^aR
	if err != nil {return nil, err}

	a := new(crypto.Commitment).SetInt(zero).AddGenerator(hAlpha).AddBy(gAl).AddBy(hAr)	//h^alpha g_^aL h_^aR
	proof.a = a

	// calculate S
	hRho := new(crypto.Generator).Mul(private.h, rho)			//h^rho

	gSl, err := new(crypto.Commitment).MultiSet(private.g_, sL)	//g_^sL
	if err != nil {return nil, err}

	hSr, err := new(crypto.Commitment).MultiSet(private.h_, sR)	//h_^sR
	if err != nil {return nil, err}

	s := new(crypto.Commitment).SetInt(zero).AddGenerator(hRho).AddBy(gSl).AddBy(hSr) //h^rho g_^sL h_^sR
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
			aLz := new(big.Int).Sub(aL[i], z)		//aL-z
			sLx := new(big.Int).Mul(sL[i], x)		//x*sL
			answer_ := new(big.Int).Add(aLz, sLx)	//(aL-z)+x*sL
			answer[i] = answer_.Mod(answer_, P)
		}
		return answer
	}

	R := func(x *big.Int) []*big.Int {
		answer := make([]*big.Int, Len)
		twoExp := big.NewInt(1)
		yExp := big.NewInt(1)
		for i := 0; i < Len; i++ {
			sRx := new(big.Int).Mul(sR[i], x)		//x*sR
			sRx.Add(sRx, z)							//x*sR+z
			sRx.Add(sRx, aR[i])						//x*sR+z+aR
			sRx.Mod(sRx, P)
			sRx.Mul(sRx, yExp)						//y^n*(x*sR+z+aR)
			z2 := new(big.Int).Exp(z, two, P)		//z^2
			z2.Mul(z2, twoExp)						//z^2*2^n
			yExp.Mul(yExp, y)
			yExp.Mod(yExp, P)
			twoExp.Mul(twoExp, two)
			twoExp.Mod(twoExp, P)
			answer_ := new(big.Int).Add(sRx, z2)	//y^n*(x*sR+z+aR)+z^2*2^n
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
	x2 := new(big.Int).Exp(x, two, P)		//x^2
	z2 := new(big.Int).Exp(z, two, P)		//z^2
	tauX := new(big.Int).Mul(tau1, x)		//tau1*x
	tauX2 := new(big.Int).Mul(tau2, x2)		//tau2*x^2
	tau := new(big.Int).Mul(z2, private.r)	//z^2*r
	tau.Add(tau, tauX)	//z^2*r+tau1*x
	tau.Add(tau, tauX2)	//z^2*r+tau1*x+tau2*x^2
	tau.Mod(tau, P)

	proof.tau = tau

	// calculate mu
	rhoX := new(big.Int).Mul(rho, x)	//rho*x
	mu := rhoX.Add(rhoX, alpha)			//alpha+rho*x
	mu.Mod(mu, P)

	proof.mu = mu

	return proof, nil
}

func (proof *RangeProof) ProofCheck(public *RangePublic) bool {
	Len := int(public.n)
	zero := big.NewInt(0)
	//one := big.NewInt(1)
	two := big.NewInt(2)
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

	// calculate t
	t, _ := innerProduct(proof.left, proof.right)

	// calculate x, y, z
	y := crypto.Hash_(proof.a, proof.s).BigInt()
	y.Mod(y, P)

	z := crypto.Hash_(proof.a, proof.s, y).BigInt()
	z.Mod(z, P)

	x := crypto.Hash_(proof.a, proof.s, proof.t1, proof.t2, y, z).BigInt()
	x.Mod(x, P)

	x2 := new(big.Int).Exp(x, two, P)	//x^2
	z_ := new(big.Int).Sub(P, z)	//-z
	z2 := new(big.Int).Exp(z, two, P)	//z^2
	z3 := new(big.Int).Mul(z, z2)		//z^3
	z3.Mod(z3, P)

	yN := big.NewInt(0)				//<1^n, y^n>
	twoN := big.NewInt(0)			//<1^n, 2^n>
	yBase := big.NewInt(1)
	twoBase := big.NewInt(1)

	for i := 0; i < Len; i++ {
		yN.Add(yN, yBase)
		twoN.Add(twoN, twoBase)
		yBase.Mul(yBase, y)
		twoBase.Mul(twoBase, two)
		yN.Mod(yN, P)
		twoN.Mod(twoN, P)
		yBase.Mod(yBase, P)
		twoBase.Mod(twoBase, P)
	}

	// calculate sigma(y, z)
	zZ2 := new(big.Int).Sub(z, z2)	// z-z^2
	zZ2.Mod(zZ2, P)

	sigma := new(big.Int).Mul(zZ2, yN)		//(z-z^2)*<1^n, y^n>
	z3twoN := new(big.Int).Mul(z3, twoN)	//z^3*<1^n, 2^n>

	sigma.Sub(sigma, z3twoN)	//(z-z^2)*<1^n, y^n>-z^3*<1^n, 2^n>
	sigma.Mod(sigma, P)

	// convert h to h'
	h_ := make([]*crypto.Generator, Len)

	yInverse := new(big.Int).ModInverse(y, P) //y^-1
	yInverseBase := big.NewInt(1)

	for i := 0; i < Len; i++ {
		h_[i] = new(crypto.Generator).Mul(public.h_[i], yInverseBase)
		yInverseBase.Mul(yInverseBase, yInverse)
		yInverseBase.Mod(yInverseBase, P)
	}

	// verify t and tau
	left := new(crypto.Commitment).FixedSet(public.g, public.h, t, proof.tau)	//tg+tau x

	vz2 := new(crypto.Commitment).Mul(public.value, z2)					//z2 V
	gSigma := new(crypto.Commitment).SetIntByGenerator(public.g, sigma)	//g sigma
	t1x := new(crypto.Commitment).Mul(proof.t1, x)						//x T1
	t2x2 := new(crypto.Commitment).Mul(proof.t2, x2)					//x2 T2
	right := vz2.AddBy(gSigma).AddBy(t1x).AddBy(t2x2)

	if !left.Cmp(right) {return false}

	//verify l, r
	sx := new(crypto.Commitment).Mul(proof.s, x)	//S^x
	hMu := new(crypto.Commitment).SetIntByGenerator(public.h, proof.mu)	//h^mu

	ghLeft := new(crypto.Commitment).SetInt(zero).AddBy(proof.a).AddBy(sx)	//A S^x
	ghRight := new(crypto.Commitment).SetInt(zero).AddBy(hMu)				//h^mu

	yBase = big.NewInt(1)
	twoBase = big.NewInt(1)

	for i := 0; i < Len; i++ {

		zyN := new(big.Int).Mul(z, yBase)		//zy^n
		z2twoN := new(big.Int).Mul(z2, twoBase)	//z^2*2^n
		zyN.Add(zyN, z2twoN)	//zy^n+z^2*2^n
		zyN.Mod(zyN, P)
		gzHzyN := new(crypto.Commitment).FixedSet(public.g_[i], h_[i], z_, zyN)	//g^(-z)h^(z^2*2^n)

		ghLeft.AddBy(gzHzyN)	//A S^x g^(-z) h^(z^2*2^n)

		yBase.Mul(yBase, y)
		yBase.Mod(yBase, P)
		twoBase.Mul(twoBase, two)
		twoBase.Mod(twoBase, P)

		gLhR := new(crypto.Commitment).FixedSet(public.g_[i], h_[i], proof.left[i], proof.right[i])	//g^l h^r
		ghRight.AddBy(gLhR)	//h^mu g^l h_^r
	}

	return ghLeft.Cmp(ghRight)
}

func (proof *RangeProof) Bytes() []byte {
	Len := len(proof.left)
	Bn256PointBytes := common.Bn256PointBits / common.ByteBits
	Bn256ZqBytes := common.Bn256ZqBits / common.ByteBits
	totalBits := 4 * common.Bn256PointBits + (2 * Len + 2) * common.Bn256ZqBits
	totalBytes := totalBits / common.ByteBits

	bytes := make([]byte ,totalBytes)
	copy(bytes[:Bn256PointBytes], proof.a.Bytes())
	copy(bytes[Bn256PointBytes:2*Bn256PointBytes], proof.s.Bytes())
	copy(bytes[2*Bn256PointBytes:3*Bn256PointBytes], proof.t1.Bytes())
	copy(bytes[3*Bn256PointBytes:4*Bn256PointBytes], proof.t2.Bytes())

	leftBase := 4*Bn256PointBytes
	rightBase := leftBase + Len*Bn256ZqBytes
	endBase := rightBase + Len*Bn256ZqBytes
	for i := 0; i < Len; i++ {
		lBytes := proof.left[i].Bytes()
		rBytes := proof.right[i].Bytes()
		copy(bytes[leftBase+(i+1)*Bn256ZqBytes-len(lBytes):leftBase+(i+1)*Bn256ZqBytes], lBytes)
		copy(bytes[rightBase+(i+1)*Bn256ZqBytes-len(rBytes):rightBase+(i+1)*Bn256ZqBytes], rBytes)
	}
	tauBytes := proof.tau.Bytes()
	muBytes := proof.mu.Bytes()

	copy(bytes[endBase+Bn256ZqBytes-len(tauBytes):endBase+Bn256ZqBytes], tauBytes)
	copy(bytes[totalBytes-len(muBytes):totalBytes], muBytes)

	return bytes
}

func (proof *RangeProof) SetBytes(b []byte) error{
	totalBytes := len(b)
	Bn256PointBytes := common.Bn256PointBits / common.ByteBits
	Bn256ZqBytes := common.Bn256ZqBits / common.ByteBits
	bufBytes := totalBytes - 4 * Bn256PointBytes - 2 * Bn256ZqBytes
	if bufBytes < 0 || bufBytes % Bn256ZqBytes != 0 {
		return errors.NewWrongInputLength(totalBytes)
	}

	Len := bufBytes / Bn256ZqBytes / 2
	proof.left, proof.right = make([]*big.Int, Len), make([]*big.Int, Len)

	proof.a = new(crypto.Commitment).SetBytes(b[:Bn256PointBytes])
	proof.s = new(crypto.Commitment).SetBytes(b[Bn256PointBytes:2*Bn256PointBytes])
	proof.t1 = new(crypto.Commitment).SetBytes(b[2*Bn256PointBytes:3*Bn256PointBytes])
	proof.t2 = new(crypto.Commitment).SetBytes(b[3*Bn256PointBytes:4*Bn256PointBytes])


	leftBase := 4*Bn256PointBytes
	rightBase := leftBase + Len*Bn256ZqBytes
	endBase := rightBase + Len*Bn256ZqBytes
	for i := 0; i < Len; i++ {
		proof.left[i] = new(big.Int).SetBytes(b[leftBase+i*Bn256ZqBytes:leftBase+(i+1)*Bn256ZqBytes])
		proof.right[i] = new(big.Int).SetBytes(b[rightBase+i*Bn256ZqBytes:rightBase+(i+1)*Bn256ZqBytes])
	}

	proof.tau = new(big.Int).SetBytes(b[endBase:endBase+Bn256ZqBytes])
	proof.mu = new(big.Int).SetBytes(b[endBase+Bn256ZqBytes:totalBytes])

	return nil
}