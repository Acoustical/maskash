package errors

import (
	"fmt"
	"math/big"
	"os"
)

func Handle(err error) {
	if err != nil {
		fmt.Printf("%s", err.Error())
		os.Exit(1)
	}
}

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
	return fmt.Sprintf("Length %d is not match with the Length %d\n", err.a, err.b)
}

// WrongInputLength input length not right
type WrongInputLength struct {
	length int
}

func NewWrongInputLength(length int) *WrongInputLength {
	return &WrongInputLength{length: length}
}

func (err *WrongInputLength) Error() string {
	return fmt.Sprintf("Can not parse the variable with length %d\n", err.length)
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
	return fmt.Sprintf("Proof value %x over range bits %d\n", err.v, err.bit)
}

// OverMaxBitError bit value too big
type OverMaxBitError struct {
	size, maxSize uint8
}

func NewOverMaxBitError(size, maxSize uint8) *OverMaxBitError{
	return &OverMaxBitError{size, maxSize}
}

func (err *OverMaxBitError) Error() string {
	return fmt.Sprintf("Bit length %d is higher than the max bit length %d\n", err.size, err.maxSize)
}

// WrongSlotModeError slot mode set wrong
type WrongSlotModeError struct {
	requireMode, inputMode uint8
}

func NewWrongSlotModeError(requireMode, inputMode uint8) *WrongSlotModeError {
	return &WrongSlotModeError{
		requireMode: requireMode,
		inputMode:   inputMode,
	}
}

func (err *WrongSlotModeError) Error() string {
	return fmt.Sprintf("this slot require mode %d but the input is mode %d\n", err.requireMode, err.inputMode)
}

// SlotContractModeNotMatchError slot mode set wrong
type SlotContractModeNotMatchError struct {}

func NewSlotContractModeNotMatchError() *SlotContractModeNotMatchError {
	return &SlotContractModeNotMatchError{}
}

func (err *SlotContractModeNotMatchError) Error() string {
	return fmt.Sprintf("The Contract Mode of this Slot Can not have more than one variables\n")
}

// NoPrivateKeyOrGrError solve error
type NoPrivateKeyOrGrError struct {}

func NewNoPrivateKeyOrGrError() *NoPrivateKeyOrGrError {
	return &NoPrivateKeyOrGrError{}
}

func (err *NoPrivateKeyOrGrError) Error() string {
	return fmt.Sprintf("This Slot cannot be solved because the private key or G^r hasn't been set\n")
}

// NonContractSlotError solve error
type NonContractSlotError struct {}

func NewNonContractSlotError() *NonContractSlotError {
	return &NonContractSlotError{}
}

func (err *NonContractSlotError) Error() string {
	return fmt.Sprintf("The Contract Slot is nil.\n")
}

// CannotSolveError solve error
type CannotSolveError struct {}

func NewCannotSolveError() *CannotSolveError {
	return &CannotSolveError{}
}

func (err *CannotSolveError) Error() string {
	return fmt.Sprintf("This value can not be solved.\n")
}

// CannotFindValueError solve error
type CannotFindValueError struct {}

func NewCannotFindValueError() *CannotFindValueError {
	return &CannotFindValueError{}
}

func (err *CannotFindValueError) Error() string {
	return fmt.Sprintf("The answer of this commitment can not be found.\n")
}
