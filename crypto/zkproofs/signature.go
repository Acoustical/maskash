package zkproofs

import (
	"fmt"
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"golang.org/x/crypto/bn256"
	"math/big"
)

type Signature struct {
	*SignatureProof
	*SignaturePrivate
}

func (sig *Signature) Init() *Signature {
	sig.SignatureProof = new(SignatureProof)
	sig.SignaturePrivate = new(SignaturePrivate)
	sig.SignaturePublic = new(SignaturePublic)
	return sig
}

func (sig *Signature) Proof() (err error) {
	sig.SignatureProof, err = new(SignatureProof).ProofGen(sig.SignaturePrivate)
	return
}

func (sig *Signature) Check() bool {
	return sig.SignatureProof.ProofCheck(sig.SignaturePublic)
}

type SignaturePublic struct {
	addr crypto.Address
	e *big.Int
}

func (public *SignaturePublic) SetPublic(addr crypto.Address, e *big.Int) *SignaturePublic {
	public.addr, public.e = addr, e
	return public
}

func (public *SignaturePublic) public() {}

type SignaturePrivate struct {
	*SignaturePublic
	h *crypto.Generator
	sk *big.Int
}

func (private *SignaturePrivate) SetPrivate(sk *big.Int, addr crypto.Address, h *crypto.Generator, e *big.Int) *SignaturePrivate {
	private.h, private.sk = h, sk
	private.SignaturePublic.SetPublic(addr, e)
	return private
}

func (private *SignaturePrivate) private() {}

type SignatureProof struct {
	k *crypto.Generator
	s *big.Int
}

func (proof *SignatureProof) ProofGen(private *SignaturePrivate) (*SignatureProof, error) {
	P := bn256.Order
	zero := big.NewInt(0)
	for {
		k, err := crypto.RandomZq(1)
		if err != nil {return nil, err}
		K := new(crypto.Generator).Init(k[0])	// K = kG
		bytes := K.Bytes()
		r := new(big.Int).SetBytes(bytes[1:])
		r.Mod(r, P)
		if r.Cmp(zero) == 0 {continue}
		k_ := new(big.Int).ModInverse(k[0], P)
		s := new(big.Int).Mul(r, private.sk)	// rd
		s.Add(s, private.e)						// z+rd
		s.Mod(s, P)
		s.Mul(s, k_)							// k^-1(z+rd)
		s.Mod(s, P)
		if s.Cmp(zero) == 0 {continue}
		proof.k, proof.s = K, s
		return proof, nil
	}
}

func (proof *SignatureProof) ProofCheck(public *SignaturePublic) bool {
	P := bn256.Order
	G := new(crypto.Generator).Init(big.NewInt(1))
	zero := big.NewInt(0)

	// find r
	r := proof.k.X()
	r.Mod(r, P)

	// check r, s == 0
	if r.Cmp(zero) == 0 || proof.s.Cmp(zero) == 0 {return false}

	r_ := new(big.Int).ModInverse(r, P)		//r^-1
	u1 := new(big.Int).Mul(public.e, r_)	//zr^-1
	u1.Neg(u1)								//-zr^-1
	u1.Mod(u1, P)
	u2 := new(big.Int).Mul(proof.s, r_)		//sr^-1
	u2.Mod(u2, P)

	H := new(crypto.Commitment).FixedSet(G, proof.k, u1, u2)
	fmt.Printf("H\n%s\n\n", H.String())
	h := new(crypto.Generator)
	h.G1 = H.G1
	// check Address
	addr := crypto.NewAddress(h)
	fmt.Printf("addr\n%x\n\n", addr)
	return addr == public.addr
}

func (proof *SignatureProof) Bytes() []byte {
	zqBytes := common.Bn256ZqBits / common.ByteBits
	pointBytes := common.Bn256PointBits / common.ByteBits
	totalLength := pointBytes + zqBytes
	bytes := make([]byte, totalLength)

	kBytes := proof.k.Bytes()
	sBytes := proof.s.Bytes()

	copy(bytes[pointBytes-len(kBytes):], kBytes)
	copy(bytes[pointBytes + zqBytes-len(sBytes):], sBytes)

	return bytes
}

func (proof *SignatureProof) SetBytes(b []byte) error {
	bLen := len(b)
	zqBytes := common.Bn256ZqBits / common.ByteBits
	pointBytes := common.Bn256PointBits / common.ByteBits
	totalLength := pointBytes + zqBytes
	if bLen != totalLength {return errors.NewWrongInputLength(bLen)}
	proof.k = new(crypto.Generator).SetBytes(b[:pointBytes])
	proof.s = new(big.Int).SetBytes(b[pointBytes:totalLength])
	return nil
}

