package errors

import (
	"fmt"
	"math/big"
)

// LengthNotMatchError length not matched
type LengthNotMatchError struct {
	a, b int
}

func NewLengthNotMatchError(a, b int) *LengthNotMatchError {
	return &LengthNotMatchError{
		a: a,
		b: b,
	}
}

func (err *LengthNotMatchError) Error() string {
	return fmt.Sprintf("Length %d is not match with the Length %d", err.a, err.b)
}

// WrongInputLength input length not right
type WrongInputLength struct {
	length int
}

func NewWrongInputLength(length int) *WrongInputLength {
	return &WrongInputLength{length: length}
}

func (err *WrongInputLength) Error() string {
	return fmt.Sprintf("Can not parse the variable with length %d", err.length)
}

// OverRangeError range proof variable v over range
type OverRangeError struct {
	bit uint8
	v *big.Int
}

func NewOverRangeError(bit uint8, v *big.Int) *OverRangeError {
	return &OverRangeError{bit, v}
}

func (err *OverRangeError) Error() string {
	return fmt.Sprintf("Proof value %x over range bits %d", err.v, err.bit)
}

// OverMaxBitError bit value too big
type OverMaxBitError struct {
	size, maxSize uint8
}

func NewOverMaxBitError(size, maxSize uint8) *OverMaxBitError{
	return &OverMaxBitError{size, maxSize}
}

func (err *OverMaxBitError) Error() string {
	return fmt.Sprintf("Bit length %d is higher than the max bit length %d", err.size, err.maxSize)
}

