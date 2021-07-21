package privacy

import "math/big"

type ActualValue struct {
	v, r *big.Int
	solvable bool
}

func NewValue(b Base, a *ActualValue) Value {
	switch b_ := b.(type) {
	case *PlaintextBase:
		return &PlaintextValue{nil, a.v}
	case *SecretBase:
		return b_.SetValue(a)
	case *AnonymousBase:
		return b_.SetValue(a)
	}
	return nil
}
