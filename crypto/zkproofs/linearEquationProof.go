package zkproofs

import (
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"golang.org/x/crypto/bn256"
	"math/big"
)

type LinearEquationZK struct {
	*LinearEquationProof
	*LinearEquationPrivate
}

func (zk *LinearEquationZK) Init() *LinearEquationZK{
	zk.LinearEquationProof = new(LinearEquationProof)
	zk.LinearEquationPrivate = new(LinearEquationPrivate)
	zk.LinearEquationPublic = new(LinearEquationPublic)
	return zk
}

func (zk *LinearEquationZK) Proof() (err error) {
	zk.LinearEquationProof, err = new(LinearEquationProof).ProofGen(zk.LinearEquationPrivate)
	return
}

func (zk *LinearEquationZK) Check() bool {
	return zk.LinearEquationProof.ProofCheck(zk.LinearEquationPublic)
}

// LinearEquationPublic contains the linear equation public variables
type LinearEquationPublic struct {
	a []*big.Int
	b *big.Int
	y *crypto.Commitment
	g []*crypto.Generator
}

// SetPublic init public
func (public *LinearEquationPublic) SetPublic(a []*big.Int, b *big.Int, y *crypto.Commitment, g []*crypto.Generator) (*LinearEquationPublic, error) {
	aLen := len(a)
	gLen := len(g)
	if aLen != gLen {
		return nil, errors.NewLengthNotMatchError(aLen, gLen)
	}
	public.a, public.b, public.y, public.g = a, b, y, g
	return public, nil
}

// public function
func (public *LinearEquationPublic) public() {}

// LinearEquationPrivate contains the linear equation public variables
type LinearEquationPrivate struct {
	*LinearEquationPublic
	x []*big.Int
}

// SetPrivate init public
func (private *LinearEquationPrivate) SetPrivate(a []*big.Int, b *big.Int, x []*big.Int, y *crypto.Commitment, g []*crypto.Generator) (*LinearEquationPrivate, error) {
	aLen := len(a)
	xLen := len(x)
	if aLen != xLen {
		return nil, errors.NewLengthNotMatchError(aLen, xLen)
	}
	private.x = x
	_, err := private.SetPublic(a, b, y, g)
	return private, err
}

// private function
func (private *LinearEquationPrivate) private() {}

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
	P := bn256.Order
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
				Ai.ModInverse(Ai, P)
				v[i] = new(big.Int).Mul(last, Ai)
				v[i].Mod(v[i], P)
				ssnum--
			} else {
				v[i] = rbi[line]
				line++
				ssnum--
				buf := new(big.Int).Mul(ai, v[i])
				last.Sub(last, buf)
				last.Mod(last, P)
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
		cx.Mod(cx, P)
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
	t, _ := new(crypto.Commitment).MultiSet(public.g, proof.s)

	yc := new(crypto.Commitment).Mul(public.y, c)
	t.Add(yc)

	if !t.Cmp(proof.t) {
		return false
	}

	// check s
	zero := big.NewInt(0)
	P := bn256.Order
	as := new(big.Int).Mul(c, public.b)
	as.Mod(as, P)
	for i := 0; i < Len; i++ {
		aisi := new(big.Int).Mul(public.a[i], proof.s[i])
		as.Add(as, aisi)
		as.Mod(as, P)
	}

	if as.Cmp(zero) == 0 {
		return true
	} else {
		return false
	}
}

// Bytes returns the bytes encode of proof
func (proof *LinearEquationProof) Bytes() []byte {
	sLen := len(proof.s)
	sBytes := common.Bn256ZqBits / common.ByteBits
	totalBits := len(proof.s) * common.Bn256ZqBits + common.Bn256PointBits
	totalBytes := totalBits / common.ByteBits

	ret := make([]byte, totalBytes)

	for i := 0; i < sLen; i++ {
		sByte := proof.s[i].Bytes()
		copy(ret[(i+1)*sBytes-len(sByte):], sByte)
	}

	tByte := proof.t.Bytes()
	copy(ret[totalBytes-len(tByte):], tByte)

	return ret
}

// SetBytes sets proof with the bytes b
func (proof *LinearEquationProof) SetBytes(b []byte) error{
	totalBytes := len(b)
	sBytes := common.Bn256ZqBits / common.ByteBits
	tBytes := common.Bn256PointBits / common.ByteBits

	if totalBytes < tBytes || (totalBytes - tBytes) % sBytes != 0 {
		return errors.NewWrongInputLength(totalBytes)
	}

	sLen := (totalBytes - tBytes) / sBytes
	proof.s = make([]*big.Int, sLen)
	for i := 0; i < sLen; i++ {
		proof.s[i] = new(big.Int).SetBytes(b[i*sBytes:(i+1)*sBytes])
	}
	proof.t = new(crypto.Commitment).SetBytes(b[sLen*sBytes:])
	return nil
}
