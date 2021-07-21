package privacy

import (
	"github.com/Acoustical/maskash/crypto/zkproofs"
	"github.com/Acoustical/maskash/errors"
)

type AuxiliaryVariables struct {
	Bases []Base
	Values []Value
	ZKs []zkproofs.ZK
}

func (aux *AuxiliaryVariables) Init(b, v, z int) *AuxiliaryVariables {
	aux.Bases = make([]Base, b)
	aux.Values = make([]Value, v)
	aux.ZKs = make([]zkproofs.ZK, z)
	return aux
}

func (aux *AuxiliaryVariables) SetBases(bs ...Base) error {
	bsLen := len(bs)
	if bsLen != len(aux.Bases) {return errors.NewWrongInputLength(bsLen)}
	copy(aux.Bases, bs)
	return nil
}

func (aux *AuxiliaryVariables) SetValues(vs ...Value) error {
	vsLen := len(vs)
	if vsLen != len(aux.Values) {return errors.NewWrongInputLength(vsLen)}
	copy(aux.Values, vs)
	return nil
}

func (aux *AuxiliaryVariables) SetZKs(zks ...zkproofs.ZK) error {
	zsLen := len(zks)
	if zsLen != len(aux.ZKs) {return errors.NewWrongInputLength(zsLen)}
	copy(aux.ZKs, zks)
	return nil
}

func (aux *AuxiliaryVariables) Child(b, v, z []int) *AuxiliaryVariables {
	bLen, vLen, zLen := len(b), len(v), len(z)
	child := new(AuxiliaryVariables).Init(bLen, vLen, zLen)
	for i := 0; i < bLen; i++ {child.Bases[i] = aux.Bases[b[i]]}
	for i := 0; i < vLen; i++ {child.Values[i] = aux.Values[v[i]]}
	for i := 0; i < zLen; i++ {child.ZKs[i] = aux.ZKs[z[i]]}
	return child
}

func (aux *AuxiliaryVariables) Match(b, v, z int) bool {
	if aux == nil {
		if b == 0 && v == 0 && z == 0 {
			return true
		} else {
			return false
		}
	} else {
		if len(aux.Bases) == b && len(aux.Values) == v && len(aux.ZKs) == z {
			return true
		} else {
			return false
		}
	}
}


