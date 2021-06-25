package privacy

import (
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/crypto/zkproofs"
	"github.com/Acoustical/maskash/errors"
	"math/big"
)

// NewAnonymousInputSlot UTXO
func NewAnonymousInputSlot(outputSlot *AnonymousSlot) *AnonymousSlot {
	slot := new(AnonymousSlot).Init()

	mode := common.Anonymous | common.InputSlot | (outputSlot.mode & common.ContractSlotMode) | (outputSlot.mode & common.Solvability)
	if outputSlot.Solvable() {mode |= common.Solvable} else {mode |= common.NonSolvable}
	_ = slot.SetMode(mode)
	slot.SetBase(outputSlot.AnonymousBase)
	slot.SetSelfValue(outputSlot.AnonymousValue)

	return slot
}

func (base *AnonymousBase) NewAnonymousOutputSlot(value, r *big.Int, solvable bool, contractMode uint8,  c ContractSlot) (*AnonymousSlot, error) {
	slot := new(AnonymousSlot).Init()

	mode := common.Anonymous | common.OutputSlot | contractMode
	if solvable {mode |= common.Solvable} else {mode |= common.NonSolvable}
	_ = slot.SetMode(mode)
	slot.SetBase(base)
	slot.SetValue(value, r)
	slot.AnonymousZK, _ = slot.Proof(value, r, slot.AnonymousValue)

	if contractMode != common.NoneContractSlot {
		if c == nil {return nil, errors.NewNonContractSlotError()}
		slot.ContractSlot = c
	}

	return slot, nil
}

type AnonymousSlot struct {
	mode uint8
	*AnonymousBase
	*AnonymousValue
	*AnonymousZK
	ContractSlot
}

func (slot *AnonymousSlot) Init() *AnonymousSlot {
	slot.AnonymousBase = new(AnonymousBase)
	slot.AnonymousValue = new(AnonymousValue)
	return slot
}

func (slot *AnonymousSlot) SlotMode() uint8 {return slot.mode}

func (slot *AnonymousSlot) CheckZKs() bool {return slot.AnonymousBase.Check(slot.AnonymousValue, slot.AnonymousZK)}

func (slot *AnonymousSlot) Base() Base {return slot.AnonymousBase}

func (slot *AnonymousSlot) Value() Value {return slot.AnonymousValue}

func (slot *AnonymousSlot) ZKs() ZKs {return slot.AnonymousZK}

func (slot *AnonymousSlot) Bytes() []byte {
	var bytes []byte
	if slot.mode & common.TxSlotKind == common.InputSlot {
		if slot.mode & common.Solvability == common.Solvable {
			bytes = make([]byte, common.AnonymousInputSolvableSlotLength)
			copy(bytes[1+common.AnonymousBaseLength:1+common.AnonymousBaseLength+common.AnonymousSolvableValueLength], slot.AnonymousValue.Bytes())
		} else {
			bytes = make([]byte, common.AnonymousInputNonSolvableSlotLength)
			copy(bytes[1+common.AnonymousBaseLength:1+common.AnonymousBaseLength+common.AnonymousNonSolvableValueLength], slot.AnonymousValue.Bytes())
		}
	} else {
		var contractLength int
		var contractBytes []byte
		if slot.mode & common.ContractSlotMode != common.NoneContractSlot {
			contractBytes = slot.ContractSlot.Bytes()
			contractLength = len(contractBytes)
		}
		if slot.mode & common.Solvability == common.Solvable {
			bytes = make([]byte, common.AnonymousOutputSolvableSlotLength+contractLength)
			copy(bytes[1+common.AnonymousBaseLength:1+common.AnonymousBaseLength+common.AnonymousSolvableValueLength], slot.AnonymousValue.Bytes())
			copy(bytes[common.AnonymousOutputSolvableSlotLength-common.AnonymousZKsLength:common.AnonymousOutputSolvableSlotLength], slot.AnonymousZK.Bytes())
			if contractLength > 0 {
				copy(bytes[common.AnonymousOutputSolvableSlotLength:], contractBytes)
			}
		} else {
			bytes = make([]byte, common.AnonymousOutputNonSolvableSlotLength+contractLength)
			copy(bytes[1+common.AnonymousBaseLength:1+common.AnonymousBaseLength+common.AnonymousNonSolvableValueLength], slot.AnonymousValue.Bytes())
			copy(bytes[common.AnonymousOutputNonSolvableSlotLength - common.AnonymousZKsLength:common.AnonymousOutputNonSolvableSlotLength], slot.AnonymousZK.Bytes())
			if contractLength > 0 {
				copy(bytes[common.AnonymousOutputNonSolvableSlotLength:], contractBytes)
			}
		}
	}
	bytes[0] = slot.mode
	copy(bytes[1:1+common.AnonymousBaseLength], slot.AnonymousBase.Bytes())
	return bytes
}

func (slot *AnonymousSlot) SetBytes(b []byte) (*AnonymousSlot, error) {
	bLen := len(b)
	if bLen < common.AnonymousInputNonSolvableSlotLength {return nil, errors.NewWrongInputLength(bLen)}
	mode := b[0]
	slot.mode = mode

	start := 1
	end := 1+common.AnonymousBaseLength
	err := slot.AnonymousBase.SetBytes(b[start:end])
	if err != nil {return nil, err}

	start = end
	if mode & common.Solvability == common.Solvable {
		end = start+common.AnonymousSolvableValueLength
	} else {
		end = start+common.AnonymousNonSolvableValueLength
	}
	_, err = slot.AnonymousValue.SetBytes(b[start:end])
	if err != nil {return nil, err}

	if mode & common.TxSlotKind == common.OutputSlot {
		start = end
		end = start + common.AnonymousZKsLength
		slot.AnonymousZK = new(AnonymousZK)
		err = slot.AnonymousZK.SetBytes(b[start:end])
		if err != nil {return nil, err}
	}

	return slot, nil
}

func (slot *AnonymousSlot) SetMode(mode uint8) error {
	if mode & common.PrivacyMode != common.Anonymous {return errors.NewWrongSlotModeError(common.Anonymous, mode)}
	slot.mode = mode
	return nil
}

func (slot *AnonymousSlot) SetBase(base *AnonymousBase) {slot.AnonymousBase = base}

func (slot *AnonymousSlot) SetValue(v, r *big.Int) {
	solvable := slot.mode & common.Solvability == common.Solvable
	slot.AnonymousValue = slot.AnonymousBase.SetValue(v, r, solvable)
}

func (slot *AnonymousSlot) SetSelfValue(value *AnonymousValue) {slot.AnonymousValue = value}


type AnonymousBase struct {g, h *crypto.Generator}

func (base *AnonymousBase) BaseMode() uint8 {return common.Anonymous}

func (base *AnonymousBase) Bytes() []byte {
	pointBytes := common.Bn256PointBits / common.ByteBits
	totalLength := common.AnonymousBaseLength
	bytes := make([]byte, totalLength)

	gBytes := base.g.Bytes()
	hBytes := base.h.Bytes()

	copy(bytes[:pointBytes], gBytes)
	copy(bytes[pointBytes:], hBytes)

	return bytes
}

func (base *AnonymousBase) SetBytes(b []byte) error {
	bLen := len(b)
	if bLen != common.AnonymousBaseLength {return errors.NewWrongInputLength(bLen)}
	pointBytes := common.Bn256PointBits / common.ByteBits

	base.g = new(crypto.Generator).SetBytes(b[:pointBytes])
	base.h = new(crypto.Generator).SetBytes(b[pointBytes:])

	return nil
}

func (base *AnonymousBase) SetValue(v, r *big.Int, solvable bool) *AnonymousValue {
	c := new(crypto.Commitment).FixedSet(base.g, base.h, v, r)
	if solvable {
		d := new(crypto.Commitment).SetIntByGenerator(base.g, r)
		return &AnonymousValue{c,d}
	} else {
		return &AnonymousValue{c,nil}
	}
}

func (base *AnonymousBase) Proof(v, r *big.Int, value *AnonymousValue) (*AnonymousZK, error) {
	if !value.Solvable() {return nil, errors.NewCannotSolveError()}

	formatZK := new(zkproofs.FormatZK).Init()
	formatZK.SetPrivate(v, r, base.g, base.h, value.c, value.d)
	err := formatZK.Proof()
	if err != nil{return nil, err}

	rangeZK := new(zkproofs.RangeZK).Init()
	_, err = rangeZK.SetPrivate(value.c, base.g, base.h, zkproofs.RangeG, zkproofs.RangeH, uint8(common.RangeProofShortBits), v, r)
	if err != nil {return nil, err}
	err = rangeZK.Proof()
	if err != nil {return nil, err}

	zk := new(AnonymousZK)
	zk.formatZK, zk.rangeZK = formatZK, rangeZK
	return zk, nil
}

func (base *AnonymousBase) Check(value *AnonymousValue, zk *AnonymousZK) bool {
	zk.formatZK.SetPublic(base.g, base.h, value.c, value.d)
	_, err := zk.rangeZK.SetPublic(value.c, base.g, base.h, zkproofs.RangeG, zkproofs.RangeH, uint8(common.RangeProofShortBits))
	if err != nil {return false}

	return zk.formatZK.Check() && zk.rangeZK.Check()
}

type AnonymousValue struct {c, d *crypto.Commitment}

func (value *AnonymousValue) ValueMode() uint8 {return common.Anonymous}

func (value *AnonymousValue) Solvable() bool {return value.d != nil}

func (value *AnonymousValue) Solve(prv *PrivateKey) (*big.Int, error) {
	if !value.Solvable() {return nil, errors.NewCannotSolveError()}
	return prv.Solve(value.c, value.d)
}

func (value *AnonymousValue) Bytes() []byte {
	var bytes []byte
	if value.Solvable() {
		pointBytes := common.Bn256PointBits / common.ByteBits
		bytes = make([]byte, common.AnonymousSolvableValueLength)
		copy(bytes[:pointBytes], value.c.Bytes())
		copy(bytes[pointBytes:], value.d.Bytes())
	} else {
		bytes = make([]byte, common.AnonymousNonSolvableValueLength)
		copy(bytes, value.c.Bytes())
	}
	return bytes
}

func (value *AnonymousValue) SetBytes(b []byte) (*AnonymousValue, error) {
	bLen := len(b)
	if bLen != common.AnonymousSolvableValueLength && bLen != common.AnonymousNonSolvableValueLength {return nil, errors.NewWrongInputLength(bLen)}
	if bLen == common.AnonymousSolvableValueLength {
		pointBytes := common.Bn256PointBits / common.ByteBits
		value.c = new(crypto.Commitment).SetBytes(b[:pointBytes])
		value.d = new(crypto.Commitment).SetBytes(b[pointBytes:])
	} else {
		value.c = new(crypto.Commitment).SetBytes(b)
	}
	return value, nil
}

type AnonymousZK struct {
	formatZK *zkproofs.FormatZK
	rangeZK *zkproofs.RangeZK
}

func (zk *AnonymousZK) ZKMode() uint8 {return common.Anonymous}

func (zk *AnonymousZK) Bytes() []byte {
	bytes := make([]byte, common.AnonymousZKsLength)

	formatProofBytes := zk.formatZK.Bytes()
	rangeProofBytes := zk.rangeZK.Bytes()

	copy(bytes[:common.FormatProofLength], formatProofBytes)
	copy(bytes[common.FormatProofLength:], rangeProofBytes)

	return bytes
}

func (zk *AnonymousZK) SetBytes(b []byte) error {
	bLen := len(b)
	if bLen != common.AnonymousZKsLength {return errors.NewWrongInputLength(bLen)}

	zk.formatZK = new(zkproofs.FormatZK).Init()
	err := zk.formatZK.SetBytes(b[:common.FormatProofLength])
	if err != nil{return err}
	zk.rangeZK = new(zkproofs.RangeZK).Init()
	err = zk.rangeZK.SetBytes(b[common.FormatProofLength:])
	if err != nil{return err}

	return nil
}

