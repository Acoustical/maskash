package zkproofs

import (
	"fmt"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"math/big"
	"testing"
)

func TestRangeProof(t *testing.T) {
	v := big.NewInt(29)
	n := 5

	fmt.Printf("Try to proof value %d in [0, 2^%d)\n\n", v, n)

	mix, _, _ := crypto.RandomPoints(2 * n + 2)
	g := mix[0]
	h := mix[1]
	g_ := mix[2:2+n]
	h_ := mix[2+n:2+2*n]

	fmt.Printf("Values of G\n%s\n\n", g.String())
	fmt.Printf("Values of H\n%s\n\n", h.String())
	fmt.Printf("Values of G_\n%x\n\n", g_)
	fmt.Printf("Values of H_\n%x\n\n", h_)

	value, r, err := new(crypto.Commitment).Set(g, h, v)
	errors.Handle(err)

	fmt.Printf("The Commitment V\n%s\n\n", value.String())
	fmt.Printf("The Commitment Mask r\n%x\n\n", r)

	fmt.Printf("Prover generate Proof...")
	zkProver := new(RangeZK).Init()
	_, err = zkProver.SetPrivate(value, g, h, g_, h_, uint8(n), v, r)
	errors.Handle(err)
	err = zkProver.Proof()
	errors.Handle(err)
	bytes := zkProver.Bytes()

	fmt.Printf("Proof Infomathon:\n%x\n\n", bytes)

	zkVerifier := new(RangeZK).Init()
	_, err = zkVerifier.SetPublic(value, g, h, g_, h_, uint8(n))
	errors.Handle(err)
	err = zkVerifier.SetBytes(bytes)
	errors.Handle(err)
	if zkVerifier.Check() {
		fmt.Println("Range Proof check success.")
	} else {
		fmt.Println("Range Proof check failed.")
	}
}
