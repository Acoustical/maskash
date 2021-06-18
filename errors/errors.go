package errors

import "fmt"

// LengthNotMatchError is the called variables' length not matched
type LengthNotMatchError struct {
	a, b int
}

func NewLengthNotMatchError(a, b int) (err *LengthNotMatchError) {
	err = new(LengthNotMatchError)
	err.a, err.b = a, b
	return
}

func (err *LengthNotMatchError) Error() string {
	return fmt.Sprintf("Length %d is not match with the Length %d", err.a, err.b)
}
