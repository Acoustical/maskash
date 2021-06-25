package crypto

import (
	"fmt"
	"math/big"
	"testing"
)

func TestPedersen(t *testing.T) {
	g := new(Generator).Init(big.NewInt(1145141919810))
	fmt.Printf("g\n%s\n\n",g.String())

	gBytes := g.Bytes()
	fmt.Printf("gBytes\n%x\n\n", gBytes)

	g0 := new(Generator).SetBytes(gBytes)

	fmt.Printf("g0\n%s\n\n",g0.String())
}
