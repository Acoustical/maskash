package zkproofs

import (
	"fmt"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"math/big"
	"testing"
)

func TestFormatProof(t *testing.T) {
	v := big.NewInt(12315)
	fmt.Printf("Value of v\n%d\n\n", v)
	mix, _, _ := crypto.RandomPoints(2)
	g, h := mix[0], mix[1]
	fmt.Printf("Value of g\n%s\n\n", g.String())
	fmt.Printf("Value of h\n%s\n\n", h.String())
	c1, r, err := new(crypto.Commitment).Set(g, h, v)
	fmt.Printf("Value of r\n%d\n\n", r)
	errors.Handle(err)
	c2 := new(crypto.Commitment).SetIntByGenerator(g, r)
	fmt.Printf("Value of c1\n%s\n\n", c1.String())
	fmt.Printf("Value of c2\n%s\n\n", c2.String())

	fmt.Printf("Prover generate Proof...")
	zkProver := new(FormatZK).Init()
	zkProver.SetPrivate(v, r, g, h, c1, c2)
	err = zkProver.Proof()
	errors.Handle(err)

	bytes := zkProver.Bytes()
	fmt.Printf("Proof Infomathon:\n%x\n\n", bytes)

	zkVerifier := new(FormatZK).Init()
	zkVerifier.SetPublic(g, h, c1, c2)
	err = zkVerifier.SetBytes(bytes)
	errors.Handle(err)
	if zkVerifier.Check() {
		fmt.Println("Format Proof check success.")
	} else {
		fmt.Println("Format Proof check success.")
	}
}
