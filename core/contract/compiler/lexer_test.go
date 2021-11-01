package compiler

import (
	"fmt"
	"testing"
)

func TestLexer(t *testing.T) {
	lc := new(LetterChain).InitFromFile("test_code.mask")
	nr := lc.head.next
	for nr != nil {
		if nr.value == nil {
			fmt.Printf("Got Symbol %s at location (%d, %d)\n", nr.typ.Name, nr.location[0], nr.location[1])
		} else {
			fmt.Printf("Got Symbol %s, Value %d at location (%d, %d)\n", nr.typ.Name, *nr.value, nr.location[0], nr.location[1])
		}
		nr = nr.next
	}
}
