package privacy

import (
	"github.com/Acoustical/maskash/common"
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/crypto/zkproofs"
	"github.com/Acoustical/maskash/errors"
	"math/big"
)

func (prv *PrivateKey) NewPlaintextInputSlot(nonce, value *big.Int) *PlaintextSlot {
	slot := new(PlaintextSlot).Init()

	_ = slot.SetMode( common.Plaintext | common.InputSlot | common.NoneContractSlot )
	slot.SetBase(prv.GenPlaintextBase())
	slot.SetValue(nonce, value)
	slot.PlaintextZK, _ = slot.Proof(prv, slot.PlaintextValue)

	return slot
}

func (base *PlaintextBase) NewPlaintextOutputSlot(value *big.Int, contractMode uint8, c ContractSlot) (*PlaintextSlot, error) {
	slot := new(PlaintextSlot).Init()

	_ = slot.SetMode( common.Plaintext | common.OutputSlot | contractMode )
	slot.SetBase(base)
	slot.SetValue(nil, value)

	if contractMode != common.NoneContractSlot {
		if c == nil {return nil, errors.NewNonContractSlotError()}
		slot.ContractSlot = c
	}
	return slot, nil
}

type PlaintextSlot struct {
	mode uint8
	*PlaintextBase
	*PlaintextValue
	*PlaintextZK
	ContractSlot
}

func (slot *PlaintextSlot) Init() *PlaintextSlot {
	slot.PlaintextBase = new(PlaintextBase)
	slot.PlaintextValue = new(PlaintextValue)
	return slot
}

func (slot *PlaintextSlot) SlotMode() uint8 {return slot.mode}

func (slot *PlaintextSlot) CheckZKs() bool {return slot.PlaintextBase.Check(slot.PlaintextValue, slot.PlaintextZK)}

func (slot *PlaintextSlot) Nonce() (*big.Int, error) {return slot.PlaintextValue.nonce, nil}

func (slot *PlaintextSlot) Base() Base {return slot.PlaintextBase}

func (slot *PlaintextSlot) Value() Value {return slot.PlaintextValue}

func (slot *PlaintextSlot) ZKs() ZKs {return slot.PlaintextZK}

func (slot *PlaintextSlot) Bytes() []byte {
	var totalLength int
	var bytes []byte
	if slot.mode & common.TxSlotKind == common.InputSlot {
		totalLength = common.PlaintextInputSlotLength
		bytes = make([]byte, totalLength)

		baseBytes := slot.PlaintextBase.Bytes()
		valueBytes := slot.PlaintextValue.Bytes()
		zkBytes := slot.PlaintextZK.Bytes()
		bytes[0] = slot.mode

		start := 1
		end := start+common.PlaintextBaseLength
		copy(bytes[start:end], baseBytes)

		start = end
		end = start + common.PlaintextInputValueLength
		copy(bytes[start:end], valueBytes)

		start = end
		end = start + common.PlaintextZKsLength
		copy(bytes[start:end], zkBytes)
	} else {
		var contractLength int
		var contractBytes []byte
		if slot.mode & common.ContractSlotMode != common.NoneContractSlot {
			contractBytes = slot.ContractSlot.Bytes()
			contractLength = len(contractBytes)
		}
		totalLength = common.PlaintextOutputSlotLength + contractLength
		bytes = make([]byte, totalLength)

		baseBytes := slot.PlaintextBase.Bytes()
		valueBytes := slot.PlaintextValue.Bytes()
		bytes[0] = slot.mode

		start := 1
		end := start+common.PlaintextBaseLength
		copy(bytes[start:end], baseBytes)

		start = end
		end = start + common.PlaintextOutputValueLength
		copy(bytes[start:end], valueBytes)

		if contractLength > 0 {
			start = end
			end = start + contractLength
			copy(bytes[start:end], contractBytes)
		}
	}

	return bytes
}

func (slot *PlaintextSlot) SetBytes(b []byte) (*PlaintextSlot, error) {
	bLen := len(b)
	if bLen == 0 {return nil, errors.NewWrongInputLength(bLen)}
	mode := b[0]
	slot.mode = mode
	if mode & common.PrivacyMode != common.Plaintext {return nil, errors.NewWrongSlotModeError(common.Plaintext, mode)}
	if mode & common.TxSlotKind == common.InputSlot {
		if bLen != common.PlaintextInputSlotLength {return nil, errors.NewWrongInputLength(bLen)}

		slot.PlaintextBase = new(PlaintextBase)
		slot.PlaintextValue = new(PlaintextValue)
		slot.PlaintextZK = new(PlaintextZK)

		start := 1
		end := start+common.PlaintextBaseLength
		err := slot.PlaintextBase.SetBytes(b[start:end])
		if err != nil {return nil, err}

		start = end
		end = start + common.PlaintextInputValueLength
		_, err = slot.PlaintextValue.SetBytes(b[start:end])
		if err != nil {return nil, err}

		start = end
		end = start + common.PlaintextZKsLength
		err = slot.PlaintextZK.SetBytes(b[start:end])
		if err != nil {return nil, err}
	} else {
		var contractLength int
		if slot.mode & common.ContractSlotMode != common.NoneContractSlot {
			contractLength = int(b[common.PlaintextOutputSlotLength]) << 8 + int(b[common.PlaintextOutputSlotLength+1]) + 2
		}
		if bLen != common.PlaintextOutputSlotLength + contractLength {return nil, errors.NewWrongInputLength(bLen)}

		slot.PlaintextBase = new(PlaintextBase)
		slot.PlaintextValue = new(PlaintextValue)

		start := 1
		end := start+common.PlaintextBaseLength
		err := slot.PlaintextBase.SetBytes(b[start:end])
		if err != nil {return nil, err}

		start = end
		end = start + common.PlaintextOutputValueLength
		_, err = slot.PlaintextValue.SetBytes(b[start:end])
		if err != nil {return nil, err}

		if contractLength > 0 {
			start = end
			end = start + contractLength
			err = slot.ContractSlot.SetBytes(b[start:end])
			if err != nil {return nil, err}
		}
	}
	return slot, nil
}

func (slot *PlaintextSlot) SetMode(mode uint8) error {
	if mode & common.PrivacyMode != common.Plaintext {return errors.NewWrongSlotModeError(common.Plaintext, mode)}
	slot.mode = mode
	return nil
}

func (slot *PlaintextSlot) SetBase(base *PlaintextBase) {slot.PlaintextBase = base}

func (slot *PlaintextSlot) SetValue(nonce, value *big.Int) {slot.PlaintextValue = slot.PlaintextBase.SetValue(nonce, value)}

type PlaintextBase struct {addr crypto.Address}

func (base *PlaintextBase) BaseMode() uint8 {return common.Plaintext}

func (base *PlaintextBase) Bytes() []byte {return base.addr[:]}

func (base *PlaintextBase) SetBytes(b []byte) error {
	bLen := len(b)
	if bLen != common.PlaintextBaseLength {return errors.NewWrongInputLength(bLen)}
	copy(base.addr[:], b)
	return nil
}

func (base *PlaintextBase) SetValue(nonce, v *big.Int) *PlaintextValue {return &PlaintextValue{nonce, v}}

func (base *PlaintextBase) Proof(prv *PrivateKey, value *PlaintextValue) (*PlaintextZK, error) {
	e := crypto.Hash_(base, value).BigInt()
	h := new(crypto.Generator).Init(prv.Int)

	sig := new(zkproofs.Signature).Init()
	sig.SetPrivate(prv.Int, base.addr, h, e)
	err := sig.Proof()
	return &PlaintextZK{sig}, err
}

func (base *PlaintextBase) Check(value *PlaintextValue, zk *PlaintextZK) bool {
	e := crypto.Hash_(base, value).BigInt()

	sig := new(zkproofs.Signature).Init()
	sig.SetPublic(base.addr, e)
	return zk.sig.Check()
}

type PlaintextValue struct {nonce, v *big.Int}

func (value *PlaintextValue) ValueMode() uint8 {return common.Plaintext}

func (value *PlaintextValue) Solvable() bool {return true}

func (value *PlaintextValue) Solve(prv *PrivateKey) (*big.Int, error) {return value.v, nil}

func (value *PlaintextValue) Bytes() []byte {
	zqBytes := common.Bn256ZqBits / common.ByteBits
	var bytes []byte
	if value.nonce == nil {
		bytes = make([]byte, common.PlaintextOutputValueLength)
		vBytes := value.v.Bytes()
		copy(bytes[zqBytes-len(vBytes):], vBytes)
	} else {
		bytes = make([]byte, common.PlaintextInputValueLength)

		nonceBytes := value.nonce.Bytes()
		vBytes := value.v.Bytes()

		copy(bytes[zqBytes-len(nonceBytes):], nonceBytes)
		copy(bytes[2*zqBytes-len(vBytes):], vBytes)
	}

	return bytes
}

func (value *PlaintextValue) SetBytes(b []byte) (*PlaintextValue, error){
	bLen := len(b)
	if bLen != common.PlaintextInputValueLength && bLen != common.PlaintextOutputValueLength {return nil, errors.NewWrongInputLength(bLen)}
	if bLen == common.PlaintextInputValueLength {
		zqBytes := common.Bn256ZqBits / common.ByteBits
		value.nonce = new(big.Int).SetBytes(b[:zqBytes])
		value.v = new(big.Int).SetBytes(b[zqBytes:])
	} else {
		value.v = new(big.Int).SetBytes(b)
	}
	return value, nil
}

type PlaintextZK struct {sig *zkproofs.Signature}

func (zk *PlaintextZK) ZKMode() uint8 {return common.Plaintext}

func (zk *PlaintextZK) Bytes() []byte {return zk.sig.Bytes()}

func (zk *PlaintextZK) SetBytes(b []byte) error {
	zk.sig = new(zkproofs.Signature).Init()
	return zk.sig.SetBytes(b)
}
