package zkproofs

import (
	"fmt"
	"github.com/Acoustical/maskash/crypto"
	"golang.org/x/crypto/bn256"
	"math/big"
	"os"
	"testing"
)

func Handle(err error) {
	if err != nil {
		fmt.Errorf("%s", err)
		os.Exit(1)
	}
}

func TestLinearEquation(t *testing.T) {
	// Generate X A G
	xa, err := crypto.RandomZq(12)
	Handle(err)
	x := xa[:4]
	a := xa[4:8]
	g := make([]*crypto.Generator, 4)
	for i := 0; i < len(g); i++ {
		g[i] = new(crypto.Generator).Init(xa[8+i])
	}

	// Calculate Y
	y, err := new(crypto.Commitment).MultiSet(g, x)
	Handle(err)

	// Calculate b
	P1 := new(big.Int).Sub(bn256.Order, big.NewInt(1))
	b := big.NewInt(0)
	for i := 0; i < len(a); i++ {
		ax := new(big.Int).Mul(a[i], x[i])
		b.Add(b, ax)
		b.Mod(b, P1)
	}

	public, err := new(LinearEquationPublic).SetPublic(a, b, y, g)
	Handle(err)
	private, err := new(LinearEquationPrivate).SetPrivate(a, b, x, y, g)
	Handle(err)

	proof, err := new(LinearEquationProof).ProofGen(private)
	Handle(err)

	if proof.ProofCheck(public) {
		fmt.Println("Linear Equation Proof check success.")
	} else {
		fmt.Println("Linear Equation Proof check failed.")
	}
}
