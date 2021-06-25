package privacy

import (
	"fmt"
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/errors"
	"math/big"
	"testing"
)

func TestPlaintext(t *testing.T) {
	prv := NewRandomPrivateKey()
	fmt.Printf("Generate Private Key\n%x\n\n", prv)

	plaintextBase := prv.GenPlaintextBase()
	fmt.Printf("Address\n%x\n\n", plaintextBase.Bytes())

	slot0 := prv.NewPlaintextInputSlot(big.NewInt(12345), big.NewInt(114514))
	slot1, err := plaintextBase.NewPlaintextOutputSlot(big.NewInt(1919810), common.NoneContractSlot, nil)
	errors.Handle(err)

	slot0Bytes := slot0.Bytes()
	slot1Bytes := slot1.Bytes()

	fmt.Printf("Slot0\n%x\n\n", slot0Bytes)
	fmt.Printf("Slot1\n%x\n\n", slot1Bytes)

	slot0bak, err := new(PlaintextSlot).SetBytes(slot0Bytes)
	errors.Handle(err)
	slot1bak, err := new(PlaintextSlot).SetBytes(slot1Bytes)
	errors.Handle(err)

	slot0Bytes = slot0bak.Bytes()
	slot1Bytes = slot1bak.Bytes()

	fmt.Printf("Slot0\n%x\n\n", slot0Bytes)
	fmt.Printf("Slot1\n%x\n\n", slot1Bytes)

	if slot0.CheckZKs() {
		fmt.Printf("Solt0 ZK check success!\n\n")
	} else {
		fmt.Printf("Solt0 ZK check failed!\n\n")
	}
}
