package crypto

import (
	"crypto/rand"
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
	g.G1.ScalarMult(a.G1, k)
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
	return g.G1.Marshal()
}

// SetBytes sets c to the result of converting the output of Marshal back into a
// group element and then returns c
func (g *Generator) SetBytes(b []byte) *Generator {
	g.G1.Unmarshal(b)
	return g
}

// Commitment is the alias of bn256.G1 represent of the Pedersen Commitment
type Commitment struct {
	*bn256.G1
}

// Set sets c to vg+rh with random r, returns c, r, err
func (c *Commitment) Set(g *Generator, h *Generator, v *big.Int) (*Commitment, *big.Int, error) {
	p0 := g.MulBy(v).G1
	P1, r, err := h.Random()
	if err != nil {
		return nil, nil, err
	}
	p1 := P1.G1
	c.G1 = new(bn256.G1).Add(p0, p1)
	return c, r, nil
}

// MultiSet sets c to sum(gv), returns c, err
func (c *Commitment) MultiSet(g []*Generator, v []*big.Int) (*Commitment, error) {
	gLen := len(g)
	vLen := len(v)
	if gLen != vLen {
		return nil, zkproofs.NewLengthNotMatchError(gLen, vLen)
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

func (c *Commitment) SetInt(k *big.Int) *Commitment {
	c.G1 = new(bn256.G1).ScalarBaseMult(k)
	return c
}

// Add sets c to c+a and returns c
func (c *Commitment) Add(a *Commitment) *Commitment {
	c.G1.Add(c.G1, a.G1)
	return c
}

// AddGenerator sets c to c+a and returns c
func (c *Commitment) AddGenerator(g *Generator) *Commitment {
	c.G1.Add(c.G1, g.G1)
	return c
}

// Neg sets c to -c and returns c
func (c *Commitment) Neg() *Commitment {
	c.G1.Neg(c.G1)
	return c
}

// Mul sets c to kc and returns c
func (c *Commitment) Mul(cm *Commitment, k *big.Int) *Commitment {
	c.G1.ScalarMult(cm.G1, k)
	return c
}

// MulBy sets c to kc and returns c
func (c *Commitment) MulBy(k *big.Int) *Commitment {
	c.G1.ScalarMult(c.G1, k)
	return c
}

// Bytes converts c to byte slice
func (c *Commitment) Bytes() []byte {
	return c.G1.Marshal()
}

// SetBytes sets c to the result of converting the output of Marshal back into a
// group element and then returns c
func (c *Commitment) SetBytes(b []byte) *Commitment {
	c.G1.Unmarshal(b)
	return c
}

// Cmp return whether c and cm is the same Commitment
func (c *Commitment) Cmp(cm *Commitment) bool {
	return c.String() == cm.String()
}
