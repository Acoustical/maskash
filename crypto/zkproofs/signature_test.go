package zkproofs

import (
	"fmt"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"testing"
)

func TestSignature(t *testing.T) {
	msgSk, _ := crypto.RandomZq(2)
	msg := msgSk[0]
	sk := msgSk[1]
	h := new(crypto.Generator).Init(sk)
	addr := crypto.NewAddress(h)

	fmt.Printf("The Msg is \n%x\n\n", msg)
	fmt.Printf("Address \n%x\n\n", addr)
	fmt.Printf("Public key \n%s\n\n", h.String())
	fmt.Printf("Private key \n%x\n\n", sk)

	zkProver := new(Signature).Init()
	zkProver.SetPrivate(sk, addr, h, msg)
	err := zkProver.Proof()
	errors.Handle(err)

	bytes := zkProver.Bytes()
	fmt.Printf("Signature \n%x\n\n", bytes)

	zkVerifier := new(Signature).Init()
	zkVerifier.SetPublic(addr, msg)
	err = zkVerifier.SetBytes(bytes)
	errors.Handle(err)
	if zkVerifier.Check() {
		fmt.Println("Signature check success.")
	} else {
		fmt.Println("Signature check failed...")
	}

}
