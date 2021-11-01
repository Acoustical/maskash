package zkproofs

import (
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"golang.org/x/crypto/bn256"
	"math/big"
)

type FormatZK struct {
	*FormatProof
	*FormatPrivate
}

func (zk *FormatZK) Init() *FormatZK {
	zk.FormatProof = new(FormatProof)
	zk.FormatPrivate = new(FormatPrivate)
	zk.FormatPublic = new(FormatPublic)
	return zk
}

func (zk *FormatZK) Proof() (err error) {
	zk.FormatProof, err = zk.FormatProof.ProofGen(zk.FormatPrivate)
	return err
}

func (zk *FormatZK) Check() bool {
	return zk.FormatProof.ProofCheck(zk.FormatPublic)
}

type FormatPublic struct {
	g, h *crypto.Generator
	c1, c2 *crypto.Commitment
}

func (public *FormatPublic) SetPublic(g, h *crypto.Generator, c1, c2 *crypto.Commitment) *FormatPublic {
	public.g, public.h, public.c1, public.c2 = g, h, c1, c2
	return public
}

func (public *FormatPublic) public() {}

type FormatPrivate struct {
	v, r *big.Int
	*FormatPublic
}

func (private *FormatPrivate) SetPrivate(v, r *big.Int, g, h *crypto.Generator, c1, c2 *crypto.Commitment) *FormatPrivate {
	private.v, private.r = v, r
	private.FormatPublic.SetPublic(g, h, c1, c2)
	return private
}

func (private *FormatPrivate) private() {}

type FormatProof struct {
	c, z1, z2 *big.Int
}

func (proof *FormatProof) ProofGen(private *FormatPrivate) (*FormatProof, error) {
	ab, err := crypto.RandomZq(2)
	if err != nil {return nil, err}
	P := bn256.Order

	a, b := ab[0], ab[1]
	t1p := new(crypto.Commitment).FixedSet(private.g, private.h, a, b)
	t2p := new(crypto.Commitment).SetIntByGenerator(private.g, b)

	c := crypto.Hash_(t1p, t2p).BigInt()
	c.Mod(c, P)

	z1 := new(big.Int).Mul(c, private.v)
	z1.Sub(a, z1)
	z1.Mod(z1, P)

	z2 := new(big.Int).Mul(c, private.r)
	z2.Sub(b, z2)
	z2.Mod(z2, P)

	proof.c = c
	proof.z1 = z1
	proof.z2 = z2
	return proof, nil
}

func (proof *FormatProof) ProofCheck(public *FormatPublic) bool {
	P := bn256.Order
	zero := big.NewInt(0)

	cc1 := new(crypto.Commitment).Mul(public.c1, proof.c)
	cc2 := new(crypto.Commitment).Mul(public.c2, proof.c)
	gz1 := new(crypto.Commitment).SetIntByGenerator(public.g, proof.z1)
	gz2 := new(crypto.Commitment).SetIntByGenerator(public.g, proof.z2)
	hz2 := new(crypto.Commitment).SetIntByGenerator(public.h, proof.z2)

	t1v := new(crypto.Commitment).SetInt(zero).AddBy(cc1).AddBy(gz1).AddBy(hz2)
	t2v := new(crypto.Commitment).SetInt(zero).AddBy(cc2).AddBy(gz2)

	c := crypto.Hash_(t1v, t2v).BigInt()
	c.Mod(c, P)

	return c.Cmp(proof.c) == 0
}

func (proof *FormatProof) Bytes() []byte {
	Bn256ZqBytes := common.Bn256ZqBits / common.ByteBits
	totalBytes := Bn256ZqBytes * 3

	bytes := make([]byte, totalBytes)
	cBytes := proof.c.Bytes()
	z1Bytes := proof.z1.Bytes()
	z2Bytes := proof.z2.Bytes()

	copy(bytes[Bn256ZqBytes-len(cBytes):], cBytes)
	copy(bytes[2*Bn256ZqBytes-len(z1Bytes):], z1Bytes)
	copy(bytes[3*Bn256ZqBytes-len(z2Bytes):], z2Bytes)

	return bytes
}

func (proof *FormatProof) SetBytes(b []byte) error {
	Bn256ZqBytes := common.Bn256ZqBits / common.ByteBits
	totalBytes := len(b)
	if totalBytes != 3*Bn256ZqBytes {return errors.NewWrongInputLength(totalBytes)}
	proof.c = new(big.Int).SetBytes(b[:Bn256ZqBytes])
	proof.z1 = new(big.Int).SetBytes(b[Bn256ZqBytes:2*Bn256ZqBytes])
	proof.z2 = new(big.Int).SetBytes(b[2*Bn256ZqBytes:])
	return nil
}