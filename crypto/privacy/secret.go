package privacy

import (
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/crypto/zkproofs"
	"github.com/Acoustical/maskash/errors"
	"math/big"
)

// NewSecretInputSlot UTXO
func NewSecretInputSlot(outputSlot *SecretSlot) *SecretSlot {
	slot := new(SecretSlot).Init()

	mode := common.Secret | common.InputSlot | (outputSlot.mode & common.ContractSlotMode) | (outputSlot.mode & common.Solvability)
	if outputSlot.Solvable() {mode |= common.Solvable} else {mode |= common.NonSolvable}
	_ = slot.SetMode(mode)
	slot.SetBase(outputSlot.SecretBase)
	slot.SetSelfValue(outputSlot.SecretValue)

	return slot
}

func (base *SecretBase) NewSecretOutputSlot(a *ActualValue, contractMode uint8,  c ContractSlot) (*SecretSlot, error) {
	slot := new(SecretSlot).Init()

	mode := common.Secret | common.OutputSlot | contractMode
	if a.solvable {mode |= common.Solvable} else {mode |= common.NonSolvable}
	_ = slot.SetMode(mode)
	slot.SetBase(base)
	slot.SetValue(a)
	slot.SecretZK, _ = slot.Proof(a.v, a.r, slot.SecretValue)

	if contractMode != common.NoneContractSlot {
		if c == nil {return nil, errors.NewNonContractSlotError()}
		slot.ContractSlot = c
	}

	return slot, nil
}

type SecretSlot struct {
	mode uint8
	*SecretBase
	*SecretValue
	*SecretZK
	ContractSlot
}

func (slot *SecretSlot) Init() *SecretSlot {
	slot.SecretBase = new(SecretBase)
	slot.SecretValue = new(SecretValue)
	return slot
}

func (slot *SecretSlot) SlotMode() uint8 {return slot.mode}

func (slot *SecretSlot) CheckZKs() bool {return slot.SecretBase.Check(slot.SecretValue, slot.SecretZK)}

func (slot *SecretSlot) Base() Base {return slot.SecretBase}

func (slot *SecretSlot) Value() Value {return slot.SecretValue}

func (slot *SecretSlot) ZKs() ZKs {return slot.SecretZK}

func (slot *SecretSlot) Bytes() []byte {
	var bytes []byte
	if slot.mode & common.Payablity == common.Payable {
		if slot.mode & common.TxSlotKind == common.InputSlot {
			if slot.mode & common.Solvability == common.Solvable {
				bytes = make([]byte, common.SecretInputSolvableSlotLength)
				copy(bytes[1+common.SecretBaseLength:1+common.SecretBaseLength+common.SecretSolvableValueLength], slot.SecretValue.Bytes())
			} else {
				bytes = make([]byte, common.SecretInputNonSolvableSlotLength)
				copy(bytes[1+common.SecretBaseLength:1+common.SecretBaseLength+common.SecretNonSolvableValueLength], slot.SecretValue.Bytes())
			}
		} else {
			var contractLength int
			var contractBytes []byte
			if slot.mode & common.ContractSlotMode != common.NoneContractSlot {
				contractBytes = slot.ContractSlot.Bytes()
				contractLength = len(contractBytes)
			}
			if slot.mode & common.Solvability == common.Solvable {
				bytes = make([]byte, common.SecretOutputSolvableSlotLength+contractLength)
				copy(bytes[1+common.SecretBaseLength:1+common.SecretBaseLength+common.SecretSolvableValueLength], slot.SecretValue.Bytes())
				copy(bytes[common.SecretOutputSolvableSlotLength-common.SecretZKsLength:common.SecretOutputSolvableSlotLength], slot.SecretZK.Bytes())
				if contractLength > 0 {
					copy(bytes[common.SecretOutputSolvableSlotLength:], contractBytes)
				}
			} else {
				bytes = make([]byte, common.SecretOutputNonSolvableSlotLength+contractLength)
				copy(bytes[1+common.SecretBaseLength:1+common.SecretBaseLength+common.SecretNonSolvableValueLength], slot.SecretValue.Bytes())
				copy(bytes[common.SecretOutputNonSolvableSlotLength - common.SecretZKsLength:common.SecretOutputNonSolvableSlotLength], slot.SecretZK.Bytes())
				if contractLength > 0 {
					copy(bytes[common.SecretOutputNonSolvableSlotLength:], contractBytes)
				}
			}
		}
	} else {
		bytes = make([]byte, 1+common.SecretBaseLength)
	}
	bytes[0] = slot.mode
	copy(bytes[1:1+common.SecretBaseLength], slot.SecretBase.Bytes())
	return bytes
}

func (slot *SecretSlot) SetBytes(b []byte) (*SecretSlot, error) {
	bLen := len(b)
	if bLen < 1+common.SecretBaseLength {return nil, errors.NewWrongInputLength(bLen)}
	mode := b[0]
	slot.mode = mode

	start := 1
	end := 1+common.SecretBaseLength
	err := slot.SecretBase.SetBytes(b[start:end])
	if err != nil {return nil, err}

	if mode & common.Payablity == common.Payable {
		start = end
		if mode & common.Solvability == common.Solvable {
			end = start+common.SecretSolvableValueLength
		} else {
			end = start+common.SecretNonSolvableValueLength
		}
		_, err = slot.SecretValue.SetBytes(b[start:end])
		if err != nil {return nil, err}

		if mode & common.TxSlotKind == common.OutputSlot {
			start = end
			end = start + common.SecretZKsLength
			slot.SecretZK = new(SecretZK)
			err = slot.SecretZK.SetBytes(b[start:end])
			if err != nil {return nil, err}
		}
	}

	return slot, nil
}

func (slot *SecretSlot) SetMode(mode uint8) error {
	if mode & common.PrivacyMode != common.Secret {return errors.NewWrongSlotModeError(common.Secret, mode)}
	slot.mode = mode
	return nil
}

func (slot *SecretSlot) SetBase(base *SecretBase) {slot.SecretBase = base}

func (slot *SecretSlot) SetValue(a *ActualValue) {slot.SecretValue = slot.SecretBase.SetValue(a)}

func (slot *SecretSlot) SetSelfValue(value *SecretValue) {slot.SecretValue = value}

type SecretBase struct {h *crypto.Generator}

func (base *SecretBase) BaseMode() uint8 {return common.Secret}

func (base *SecretBase) Bytes() []byte {return base.h.Bytes()}

func (base *SecretBase) SetBytes(b []byte) error {
	bLen := len(b)
	if bLen != common.SecretBaseLength {return errors.NewWrongInputLength(bLen)}
	base.h = new(crypto.Generator).SetBytes(b)
	return nil
}

func (base *SecretBase) SetValue(a *ActualValue) *SecretValue {
	g := new(crypto.Generator).Init(big.NewInt(1))
	c := new(crypto.Commitment).FixedSet(g, base.h, a.v, a.r)
	if a.solvable {
		d := new(crypto.Commitment).SetIntByGenerator(g, a.r)
		return &SecretValue{c,d}
	} else {
		return &SecretValue{c,nil}
	}
}

func (base *SecretBase) Proof(v, r *big.Int, value *SecretValue) (*SecretZK, error) {
	if !value.Solvable() {return nil, errors.NewCannotSolveError()}
	g := new(crypto.Generator).Init(big.NewInt(1))

	formatZK := new(zkproofs.FormatZK).Init()
	formatZK.SetPrivate(v, r, g, base.h, value.c, value.d)
	err := formatZK.Proof()
	if err != nil{return nil, err}

	rangeZK := new(zkproofs.RangeZK).Init()
	_, err = rangeZK.SetPrivate(value.c, g, base.h, zkproofs.RangeG, zkproofs.RangeH, uint8(common.RangeProofShortBits), v, r)
	if err != nil {return nil, err}
	err = rangeZK.Proof()
	if err != nil {return nil, err}

	zk := new(SecretZK)
	zk.formatZK, zk.rangeZK = formatZK, rangeZK
	return zk, nil
}

func (base *SecretBase) Check(value *SecretValue, zk *SecretZK) bool {
	g := new(crypto.Generator).Init(big.NewInt(1))

	zk.formatZK.SetPublic(g, base.h, value.c, value.d)
	_, err := zk.rangeZK.SetPublic(value.c, g, base.h, zkproofs.RangeG, zkproofs.RangeH, uint8(common.RangeProofShortBits))
	if err != nil {return false}

	return zk.formatZK.Check() && zk.rangeZK.Check()
}

type SecretValue struct {c, d *crypto.Commitment}

func (value *SecretValue) ValueMode() uint8 {
	if value.Solvable() {return common.Secret | common.Solvable} else {return common.Secret | common.NonSolvable}
}

func (value *SecretValue) Solvable() bool {return value.d != nil}

func (value *SecretValue) Solve(prv *PrivateKey) (*big.Int, error) {
	if !value.Solvable() {return nil, errors.NewCannotSolveError()}
	return prv.Solve(value.c, value.d)
}

func (value *SecretValue) Bytes() []byte {
	var bytes []byte
	if value.Solvable() {
		pointBytes := common.Bn256PointBits / common.ByteBits
		bytes = make([]byte, common.SecretSolvableValueLength)
		copy(bytes[:pointBytes], value.c.Bytes())
		copy(bytes[pointBytes:], value.d.Bytes())
	} else {
		bytes = make([]byte, common.SecretNonSolvableValueLength)
		copy(bytes, value.c.Bytes())
	}
	return bytes
}

func (value *SecretValue) SetBytes(b []byte) (*SecretValue, error) {
	bLen := len(b)
	if bLen != common.SecretSolvableValueLength && bLen != common.SecretNonSolvableValueLength {return nil, errors.NewWrongInputLength(bLen)}
	if bLen == common.SecretSolvableValueLength {
		pointBytes := common.Bn256PointBits / common.ByteBits
		value.c = new(crypto.Commitment).SetBytes(b[:pointBytes])
		value.d = new(crypto.Commitment).SetBytes(b[pointBytes:])
	} else {
		value.c = new(crypto.Commitment).SetBytes(b)
	}
	return value, nil
}

type SecretZK struct {
	formatZK *zkproofs.FormatZK
	rangeZK *zkproofs.RangeZK
}

func (zk *SecretZK) ZKMode() uint8 {return common.Secret}

func (zk *SecretZK) Bytes() []byte {
	bytes := make([]byte, common.SecretZKsLength)

	formatProofBytes := zk.formatZK.Bytes()
	rangeProofBytes := zk.rangeZK.Bytes()

	copy(bytes[:common.FormatProofLength], formatProofBytes)
	copy(bytes[common.FormatProofLength:], rangeProofBytes)

	return bytes
}

func (zk *SecretZK) SetBytes(b []byte) error {
	bLen := len(b)
	if bLen != common.SecretZKsLength {return errors.NewWrongInputLength(bLen)}

	zk.formatZK = new(zkproofs.FormatZK).Init()
	err := zk.formatZK.SetBytes(b[:common.FormatProofLength])
	if err != nil{return err}
	zk.rangeZK = new(zkproofs.RangeZK).Init()
	err = zk.rangeZK.SetBytes(b[common.FormatProofLength:])
	if err != nil{return err}

	return nil
}
