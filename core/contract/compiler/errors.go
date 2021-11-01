package compiler

import (
	"fmt"
	"os"
)

func Alert(err Error) {
	fmt.Printf("\033[1;31;40mERROR:%s\nat [%d, %d].", err.ErrorMessage(), err.Location()[0], err.Location()[1])
	os.Exit(1)
}

type Error interface {
	Location() [2]uint
	ErrorMessage() string
}

type ErrorLocation struct {
	location [2]uint
}

func (el *ErrorLocation) New(location [2]uint) *ErrorLocation {
	el.location = location
	return el
}

func (el *ErrorLocation) Location() [2]uint {
	return el.location
}

type DuplicateDefinedError struct {
	*ErrorLocation
	varName string
}

func (err *DuplicateDefinedError) New(location [2]uint, varName string) *DuplicateDefinedError {
	err.ErrorLocation = new(ErrorLocation).New(location)
	err.varName = varName
	return err
}

func (err *DuplicateDefinedError) ErrorMessage() string {
	return fmt.Sprintf("The variable %s has already been declared!", err.varName)
}

type WrongIndentError struct {
	*ErrorLocation
}

func (err *WrongIndentError) New(location [2]uint) *WrongIndentError {
	err.ErrorLocation = new(ErrorLocation).New(location)
	return err
}

func (err *WrongIndentError) ErrorMessage() string {
	return fmt.Sprintf("Wrong indent detected!")
}

type UnexpectedSymbolError struct {
	sym string
	*ErrorLocation
}

func (err *UnexpectedSymbolError) New(sym string, location [2]uint) *UnexpectedSymbolError {
	err.ErrorLocation = new(ErrorLocation).New(location)
	err.sym = sym
	return err
}

func (err *UnexpectedSymbolError) ErrorMessage() string {
	if len(err.sym) == 0 {
		return fmt.Sprintf("Unexpected Symbol EOF !")
	} else {
		return fmt.Sprintf("Unexpected Symbol %s !", err.sym)
	}
}






