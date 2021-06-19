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
	fmt.Printf("Values of X\n%x\n\n", x)
	a := xa[4:8]
	fmt.Printf("Values of A\n%x\n\n", a)
	g := make([]*crypto.Generator, 4)
	for i := 0; i < len(g); i++ {
		g[i] = new(crypto.Generator).Init(xa[8+i])
		fmt.Printf("Values of G[%d]\n%s %d\n\n",i ,g[i].String(), len(g[i].Bytes()))
	}

	// Calculate Y
	y, err := new(crypto.Commitment).MultiSet(g, x)
	Handle(err)
	fmt.Printf("Values of Y\n%s\n\n", y.String())

	// Calculate B
	P := bn256.Order
	b := big.NewInt(0)
	for i := 0; i < len(a); i++ {
		ax := new(big.Int).Mul(a[i], x[i])
		b.Add(b, ax)
		b.Mod(b, P)
	}
	fmt.Printf("Values of B\n%x\n\n", b)

	zkProver := new(LinearEquationZK).Init()
	_, err = zkProver.SetPrivate(a, b, x, y, g)
	Handle(err)

	fmt.Printf("Prover generate Proof...\n")
	err = zkProver.Proof()
	Handle(err)

	proofBytes := zkProver.Bytes()
	fmt.Printf("Proof Infomation:\n%x\n\n", proofBytes)


	fmt.Printf("Verifier check the Proof...\n")
	zkVerifier := new(LinearEquationZK).Init()
	_, err = zkVerifier.SetPublic(a, b, y, g)
	Handle(err)
	err = zkVerifier.SetBytes(proofBytes)
	Handle(err)

	if zkVerifier.Check() {
		fmt.Println("Linear Equation Proof check success.")
	} else {
		fmt.Println("Linear Equation Proof check failed.")
	}
}
