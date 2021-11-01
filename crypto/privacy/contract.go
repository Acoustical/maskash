package privacy

import (
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/errors"
	"math/big"
)

type ContractSlot interface {
	ContractSlotMode() uint8
	SetBytes(b []byte) error
	crypto.HashVariable
}

type ContractCreateSlot struct {binaryCode *big.Int}

func (slot *ContractCreateSlot) ContractSlotMode() uint8 {return common.ContractCreation}

func (slot *ContractCreateSlot) Bytes() []byte {
	binary := slot.binaryCode.Bytes()
	bLen := len(binary)
	bytes := make([]byte, 2 + bLen)
	bLenUint16 := uint16(bLen)

	bytes[0] = uint8(bLenUint16 >> 8)
	bytes[1] = uint8(bLenUint16 & 0b11111111)

	copy(bytes[2:], binary)
	return bytes
}

func (slot *ContractCreateSlot) SetBytes(b []byte) error {
	bLen := len(b)
	if bLen < 2 {return errors.NewWrongInputLength(bLen)}
	var length = uint16(b[0]) << 8 + uint16(b[1])
	if length != uint16(bLen - 2) {return errors.NewWrongInputLength(bLen)}
	slot.binaryCode = new(big.Int).SetBytes(b[2:])
	return nil
}

type ContractCallSlot struct {
	function Value
	bases []Base
	values []Value
	zks []ZKs
}

func (slot *ContractCallSlot) ContractSlotMode() uint8 {return common.ContractCall}

type ContractReceiptSlot struct {
	prvHash Value
	bases []Base
	values []Value
	zks []ZKs
}

func (slot *ContractReceiptSlot) ContractSlotMode() uint8 {return common.ContractReceipt}


