package privacy

import (
	"fmt"
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/errors"
	"math/big"
	"testing"
)

func TestAnonymous(t *testing.T) {
	prv := NewRandomPrivateKey()
	anonymousBase := prv.GenAnonymousBase()

	sBytes := anonymousBase.Bytes()
	fmt.Printf("anonymousBase\n%x\n\n", sBytes)

	targetBase := new(AnonymousBase)
	err := targetBase.SetBytes(sBytes)
	errors.Handle(err)

	value := big.NewInt(114514)
	knowledge, err := new(Knowledge).Init(value, true)
	errors.Handle(err)

	slot0, err := targetBase.NewAnonymousOutputSlot(knowledge, common.NoneContractSlot, nil)
	errors.Handle(err)

	if slot0.CheckZKs() {
		fmt.Printf("Solt0 ZK check success!\n\n")
	} else {
		fmt.Printf("Solt0 ZK check failed!\n\n")
	}

	slot0Bytes := slot0.Bytes()
	fmt.Printf("slot0\n%x\n\n", slot0Bytes)

	slot1 := new(AnonymousSlot).Init()
	_, err = slot1.SetBytes(slot0Bytes)
	errors.Handle(err)

	slot1Bytes := slot1.Bytes()
	fmt.Printf("slot1\n%x\n\n", slot1Bytes)

	if slot1.CheckZKs() {
		fmt.Printf("Solt1 ZK check success!\n\n")
	} else {
		fmt.Printf("Solt1 ZK check failed!\n\n")
	}

	slot2 := NewAnonymousInputSlot(slot1)
	slot2Bytes := slot2.Bytes()

	fmt.Printf("slot2\n%x\n\n", slot2Bytes)
}

