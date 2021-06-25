package crypto

import (
	"crypto/rand"
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/errors"
	"golang.org/x/crypto/bn256"
	"math/big"
)

// RandomZq returns n size of random number in Zq
func RandomZq(n int) ([]*big.Int, error) {
	num := make([]*big.Int, n)
	limit := new(big.Int).Sub(bn256.Order, new(big.Int).SetInt64(4))
	limits := new(big.Int).Exp(limit, big.NewInt(int64(n)), nil)
	mix, err := rand.Int(rand.Reader, limits)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		buf := new(big.Int).Mod(mix, limit)
		num[i] = big.NewInt(0)
		num[i].Add(buf, new(big.Int).SetUint64(2))
		if i < n-1 {
			mix.Div(mix, limit)
		}
	}
	return num, nil
}

// RandomPoints returns n size of random number in Scalar
func RandomPoints(n int) ([]*Generator, []*big.Int, error) {
	k, err := RandomZq(n)
	if err != nil{return nil, nil, err}

	g := make([]*Generator, n)
	for i := 0; i < n; i++ {
		g[i] = new(Generator).Init(k[i])
	}

	return g, k, nil
}

// Generator is a curve generator
type Generator struct {
	*bn256.G1
}

// Init sets Generator g to vg0 and returns g
func (g *Generator) Init(k *big.Int) *Generator {
	g.G1 = new(bn256.G1).ScalarBaseMult(k)
	return g
}

// Mul sets Generator g to ka and returns g
func (g *Generator) Mul(a *Generator, k *big.Int) *Generator {
	g.G1 = new(bn256.G1).ScalarMult(a.G1, k)
	return g
}

// MulBy sets Generator g to kg and returns g
func (g *Generator) MulBy(k *big.Int) *Generator {
	g.G1.ScalarMult(g.G1, k)
	return g
}

// Random sets c to rg with random r, returns c, r, error
func (g *Generator) Random() (*Generator, *big.Int, error) {
	ks, err := RandomZq(1)
	k := ks[0]
	return g.MulBy(k), k, err
}

// Bytes converts c to byte slice
func (g *Generator) Bytes() []byte {
	return ToBytes(g.G1)
}

// SetBytes sets c to the result of converting the output of Marshal back into a
// group element and then returns c
func (g *Generator) SetBytes(b []byte) *Generator {
	g.G1, _ = SetBytes(b)
	return g
}

func (g *Generator) X() *big.Int {return x(g.G1)}

func (g *Generator) Y() *big.Int {return y(g.G1)}

// Commitment is the alias of bn256.G1 represent of the Pedersen Commitment
type Commitment struct {
	*bn256.G1
}

// Set sets c to vg+rh with random r, returns c, r, err
func (c *Commitment) Set(g *Generator, h *Generator, v *big.Int) (*Commitment, *big.Int, error) {
	p0 := new(Commitment).SetIntByGenerator(g, v)
	r, err := RandomZq(1)
	if err != nil {
		return nil, nil, err
	}
	p1 := new(Commitment).SetIntByGenerator(h, r[0])
	c.G1 = new(bn256.G1).Add(p0.G1, p1.G1)
	return c, r[0], nil
}

// FixedSet sets c to vg+rh returns c, r, err
func (c *Commitment) FixedSet(g *Generator, h *Generator, v *big.Int, r *big.Int) *Commitment {
	p0 := new(Commitment).SetIntByGenerator(g, v)
	p1 := new(Commitment).SetIntByGenerator(h, r)
	c.G1 = new(bn256.G1).Add(p0.G1, p1.G1)
	return c
}

// MultiSet sets c to sum(gv), returns c, err
func (c *Commitment) MultiSet(g []*Generator, v []*big.Int) (*Commitment, error) {
	gLen := len(g)
	vLen := len(v)
	if gLen != vLen {
		return nil, errors.NewLengthNotMatchError(gLen, vLen)
	}
	c.SetInt(big.NewInt(0))
	for i := 0; i < gLen; i++ {
		c.AddGenerator(new(Generator).Mul(g[i], v[i]))
	}
	return c, nil
}

// MultiSetRandom sets c to sum(gv) which v is a set of random numbers, returns c, v, err
func (c *Commitment) MultiSetRandom(g []*Generator) (*Commitment, []*big.Int, error) {
	v, err := RandomZq(len(g))
	if err != nil {
		return nil, nil, err
	}
	_, err = c.MultiSet(g, v)
	return c, v, err
}

// SetInt set c to gk
func (c *Commitment) SetInt(k *big.Int) *Commitment {
	c.G1 = new(bn256.G1).ScalarBaseMult(k)
	return c
}

// SetIntByGenerator set c to gk
func (c *Commitment) SetIntByGenerator(g *Generator, k *big.Int) *Commitment {
	c.G1 = new(bn256.G1).ScalarMult(g.G1, k)
	return c
}

// AddBy sets c to c+a and returns c
func (c *Commitment) AddBy(a *Commitment) *Commitment {
	c.G1.Add(c.G1, a.G1)
	return c
}

// Add sets c to a+b and returns c
func (c *Commitment) Add(a, b *Commitment) *Commitment {
	c.G1.Add(a.G1, b.G1)
	return c
}

// AddGenerator sets c to c+a and returns c
func (c *Commitment) AddGenerator(g *Generator) *Commitment {
	c.G1 = new(bn256.G1).Add(c.G1, g.G1)
	return c
}

// Neg sets c to -c and returns c
func (c *Commitment) Neg() *Commitment {
	c.G1.Neg(c.G1)
	return c
}

// Mul sets c to kc and returns c
func (c *Commitment) Mul(cm *Commitment, k *big.Int) *Commitment {
	c.G1 = new(bn256.G1).ScalarMult(cm.G1, k)
	return c
}

// MulBy sets c to kc and returns c
func (c *Commitment) MulBy(k *big.Int) *Commitment {
	c.G1.ScalarMult(c.G1, k)
	return c
}

// Bytes converts c to byte slice
func (c *Commitment) Bytes() []byte {
	return ToBytes(c.G1)
}

// SetBytes sets c to the result of converting the output of Marshal back into a
// group element and then returns c
func (c *Commitment) SetBytes(b []byte) *Commitment {
	c.G1, _ = SetBytes(b)
	return c
}

// Cmp return whether c and cm is the same Commitment
func (c *Commitment) Cmp(cm *Commitment) bool {
	return c.String() == cm.String()
}

func (c *Commitment) X() *big.Int {return x(c.G1)}

func (c *Commitment) Y() *big.Int {return y(c.G1)}

func ToBytes(g *bn256.G1) []byte {
	one := big.NewInt(1)
	two := big.NewInt(2)
	zqBytes := common.Bn256ZqBits / common.ByteBits
	raw := g.Marshal()
	xBytes := raw[:zqBytes]
	y := y(g)
	y.Mod(y, two)
	var sign byte
	if y.Cmp(one) == 0 {sign = 3} else {sign = 2}
	bytes := make([]byte, common.Bn256PointBits / common.ByteBits)
	bytes[0] = sign
	copy(bytes[1:], xBytes)
	return bytes
}

func SetBytes(b []byte) (*bn256.G1, error) {
	P, _ := new(big.Int).SetString("65000549695646603732796438742359905742825358107623003571877145026864184071783", 10)
	zero := big.NewInt(0)
	one := big.NewInt(1)
	PGOne := new(big.Int).Sub(P, one)
	two := big.NewInt(2)
	curveB := big.NewInt(3)
	bLen := len(b)
	if bLen != common.Bn256PointBits / common.ByteBits {return nil, errors.NewWrongInputLength(bLen)}
	sign := b[0]
	var y *big.Int
	x := new(big.Int).SetBytes(b[1:])
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curveB)
	x3.Mod(x3, P)
	P1div2, _ := new(big.Int).SetString("32500274847823301866398219371179952871412679053811501785938572513432092035891", 10)
	P11div2, _ := new(big.Int).SetString("32500274847823301866398219371179952871412679053811501785938572513432092035892", 10)
	for i:=big.NewInt(1); i.Cmp(P) < 0; i.Add(i,one) {
		a2N := new(big.Int).Exp(i, two, P)
		a2N.Sub(a2N, x3)
		a2N.Mod(a2N, P)

		vrf := new(big.Int).Exp(a2N, P1div2, P)
		if vrf.Cmp(PGOne) == 0 {
			Pow := func(a, b, n *big.Int) (ar *big.Int){
				ar = big.NewInt(1)
				br := big.NewInt(0)
				as := new(big.Int).Set(a)
				bs := new(big.Int).Set(b)
				for n.Cmp(zero) != 0 {
					buf := new(big.Int).And(n, one)
					if buf.Cmp(one) == 0 {
						arn := new(big.Int).Mul(ar, as)
						b0 := new(big.Int).Mul(br, bs)
						b0.Mul(b0, a2N)
						arn.Add(arn, b0)
						arn.Mod(arn, P)

						brn := new(big.Int).Mul(br, as)
						brn.Add(brn, new(big.Int).Mul(ar, bs))
						brn.Mod(brn, P)

						ar.Set(arn)
						br.Set(brn)
					}
					asn := new(big.Int).Mul(as, as)
					b0 := new(big.Int).Mul(bs, bs)
					b0.Mul(b0, a2N)
					asn.Add(asn, b0)
					asn.Mod(asn, P)

					bsn := new(big.Int).Mul(bs, as)
					bsn.Mul(bsn, two)
					bsn.Mod(bsn, P)

					as.Set(asn)
					bs.Set(bsn)

					n.Rsh(n, 1)
				}
				return
			}
			y = Pow(i, one, P11div2)
			mod := new(big.Int).Mod(y, two)
			if (sign == uint8(3) && mod.Cmp(zero) == 0) || (sign == uint8(2) && mod.Cmp(one) == 0) {y.Sub(P, y)}
			if IsOnCurve(x, y) {
				bytes := make([]byte, common.Bn256ZqBits * 2 / common.ByteBits)
				copy(bytes[:], b[1:])
				yBytes := y.Bytes()
				copy(bytes[common.Bn256ZqBits * 2 / common.ByteBits - len(yBytes):], yBytes)
				g, _ := new(bn256.G1).Unmarshal(bytes)
				return g, nil
			} else {
				return nil, nil
			}
		}
	}
	return nil, nil
}

func IsOnCurve(x, y *big.Int) bool {
	P, _ := new(big.Int).SetString("65000549695646603732796438742359905742825358107623003571877145026864184071783", 10)
	curveB := big.NewInt(3)
	yy := new(big.Int).Mul(y, y)
	xxx := new(big.Int).Mul(x, x)
	xxx.Mul(xxx, x)
	xxx.Mod(xxx, P)
	yy.Mod(yy, P)
	yy.Sub(yy, xxx)
	yy.Sub(yy, curveB)
	if yy.Sign() < 0 || yy.Cmp(P) >= 0 {
		yy.Mod(yy, P)
	}
	return yy.Sign() == 0
}

func x(g *bn256.G1) *big.Int {
	xBytes := g.Marshal()[:common.Bn256ZqBits / common.ByteBits]
	x_ := new(big.Int).SetBytes(xBytes)
	return x_
}

func y(g *bn256.G1) *big.Int {
	yBytes := g.Marshal()[common.Bn256ZqBits / common.ByteBits:]
	y_ := new(big.Int).SetBytes(yBytes)
	return y_
}
