package compiler

import slr1 "github.com/Acoustical/maskash/core/contract/slr"

type SymbolStack struct {
	top *SymbolNode
}

func (ss *SymbolStack) New(status *slr1.Status) *SymbolStack {
	ss.top = new(SymbolNode).New(nil, status, nil)
	return ss
}

func (ss *SymbolStack) Push(symbol *slr1.Symbol, status *slr1.Status, value *int)  {
	sn := new(SymbolNode).New(symbol, status, value)
	sn.next = ss.top
	ss.top = sn
}

func (ss *SymbolStack) Peek() *slr1.Status {
	return ss.top.sts
}

func (ss *SymbolStack) Pop() (*slr1.Symbol, *int) {
	pop := ss.top
	ss.top = pop.next
	return pop.typ, pop.value
}

type SymbolNode struct {
	typ *slr1.Symbol
	sts *slr1.Status
	value *int
	next *SymbolNode
}

func (sn *SymbolNode) New(typ *slr1.Symbol, status *slr1.Status, value *int) *SymbolNode {
	sn.typ, sn.sts, sn.value, sn.next = typ, status, value,nil
	return sn
}

func (lc *LetterChain) Reduce()  {
	r := lc.head.next
	action := GrammarParser.Action()
	goto_ := GrammarParser.Goto()
	status := GrammarParser.StartStatus()
	ss := new(SymbolStack).New(status)
	for {
		nextStatus, product := action(status, r.typ)
		if nextStatus != nil {
			if r.typ == nil {
				Alert(new(UnexpectedSymbolError).New("", r.location))
			} else {
				ss.Push(r.typ, nextStatus, r.value)
			}
			r = r.next
			status = nextStatus
		} else if product != nil {
			for i := len(product.Eqs)-1; i >= 0; i-- {

			}
		}
	}
}