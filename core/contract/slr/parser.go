package slr1

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

type Parser struct {
	reader io.Reader
	terminators []*Symbol
	nonTerminators []*Symbol
	productions []*ProductRule
	status []*Status
	terminatorsID map[*Symbol]int
	nonTerminatorsID map[*Symbol]int
	productionsID map[*ProductRule]int
	statusID map[*Status]int
	symbolList map[string]*Symbol
	table *LRTable
}

func (p *Parser) New(reader io.Reader) *Parser {
	p.reader = reader
	p.terminators = make([]*Symbol, 0)
	p.nonTerminators = make([]*Symbol, 0)
	p.productions = make([]*ProductRule, 0)
	p.status = make([]*Status, 0)
	p.terminatorsID = make(map[*Symbol]int)
	p.nonTerminatorsID = make(map[*Symbol]int)
	p.productionsID = make(map[*ProductRule]int)
	p.statusID = make(map[*Status]int)
	p.symbolList = make(map[string]*Symbol)
	p.table = new(LRTable).New()
	p.Parse()
	p.FindDFA()
	p.FindFirst()
	p.FindFollow()
	p.BuildTable()
	return p
}

func (p *Parser) AddSymbol(str string) *Symbol {
	var sb *Symbol
	if p.symbolList[str] == nil {
		sb = new(Symbol).New(str)
		if sb == nil {
			return nil
		}
		if sb.Type {
			p.terminatorsID[sb] = len(p.terminators)
			p.terminators = append(p.terminators, sb)
		} else {
			p.nonTerminatorsID[sb] = len(p.nonTerminatorsID)
			p.nonTerminators = append(p.nonTerminators, sb)
		}
		p.symbolList[str] = sb
	} else {
		sb = p.symbolList[str]
	}
	return sb
}

func (p *Parser) AddProduct(pd *ProductRule) {
	p.productionsID[pd] = len(p.productions)
	p.productions = append(p.productions, pd)
}

func (p *Parser) AddStatue(s *Status) {
	p.statusID[s] = len(p.status)
	p.status = append(p.status, s)
}

func (p *Parser) Parse() {
	r := bufio.NewReader(p.reader)
	raw, err := r.ReadString('\n')
	for err != io.EOF && len(raw) > 0 {
		raw = strings.TrimSpace(raw)
		parts := strings.Split(raw, "->")

		left := strings.TrimSpace(parts[0])
		LFT := p.AddSymbol(left)

		right := strings.Split(parts[1], "|")
		for i := 0; i < len(right); i++ {
			rightPart := right[i]
			RTPart := strings.TrimSpace(rightPart)
			rightSingleSymbols := strings.Fields(RTPart)
			rLen := len(rightSingleSymbols)
			var rtSymbols []*Symbol
			if rLen == 1 && rightSingleSymbols[0] == "x" {
				rtSymbols = make([]*Symbol, 0)
			} else {
				rtSymbols = make([]*Symbol, rLen)
				for i := 0; i < rLen; i++ {
					rtSymbols[i] = p.AddSymbol(rightSingleSymbols[i])
				}
			}
			pd := new(ProductRule).New(LFT, rtSymbols)
			LFT.AddProduct(pd)
			p.AddProduct(pd)
		}
		raw, err = r.ReadString('\n')
	}
}

func (p *Parser) FindDFA() {
	if len(p.productions) == 0 {
		return
	}
	startPoint := []*ProductRule{p.productions[0].ExportToPrefix()}
	startRaw := new(RawStatus).New(startPoint)
	start := new(Status).New(startRaw)
	var find func(status *Status)
	find = func(status *Status) {
		p.AddStatue(status)
		syms, next := status.NextStatus()
		Len := len(syms)
		for i := 0; i < Len; i++ {
			var nowStatus *Status
			for _, st := range p.status {
				if st.CmpRaw(next[i]) {
					nowStatus = st
					break
				}
			}
			if nowStatus == nil {
				nowStatus = new(Status).New(next[i])
				find(nowStatus)
			}
			status.Next[syms[i]] = nowStatus
		}
	}
	find(start)
}

func (p *Parser) FindFirst()  {
	symbolUsed := make(map[*Symbol]bool)
	echo := func(symbol *Symbol) ([]*Symbol, bool) {
		tp := false
		for i := 0; i < len(symbol.First); i++ {
			if symbol.First[i] == nil {
				tp = true
				break
			}
		}
		return symbol.First, tp
	}
	var find func(symbol *Symbol) ([]*Symbol, bool)
	find = func(symbol *Symbol) ([]*Symbol, bool) {
		symbolUsed[symbol] = true
		if symbol.Type {
			symbol.AddFirst(symbol)
			return symbol.First, false
		} else {
			sig := true
			DelayProductions := make([]*ProductRule, 0)
			pLen := len(symbol.Productions)
			for i := 0; i < pLen; i++ {
				pd := symbol.Productions[i]
				if len(pd.Eqs) == 0 {
					symbol.AddFirst(nil)
					sig = true
				} else if pd.Eqs[0].Cmp(symbol) {
					DelayProductions = append(DelayProductions, symbol.Productions[i])
				} else {
					for j := 0; j < len(pd.Eqs); j++ {
						sb := pd.Eqs[j]
						var first []*Symbol
						var sign bool
						if _, ok := symbolUsed[sb]; ok {
							first, sign = echo(sb)
						} else {
							first, sign = find(sb)
						}
						for k := 0; k < len(first); k++ {
							symbol.AddFirst(first[k])
						}
						if sign {
							symbol.AddFirst(nil)
						}
						if !sign {
							sig = false
							break
						}
					}
				}
			}

			for i := 0; i < len(DelayProductions); i++ {
				pd := DelayProductions[i]
				for j := 0; j < len(pd.Eqs); j++ {
					sb := pd.Eqs[j]
					var first []*Symbol
					var sign bool
					if _, ok := symbolUsed[sb]; ok {
						first, sign = echo(sb)
					} else {
						first, sign = find(sb)
					}
					for k := 0; k < len(first); k++ {
						symbol.AddFirst(first[k])
					}
					if sign {
						symbol.AddFirst(nil)
					}
					if !sign {
						sig = false
						break
					}
				}
			}
			return symbol.First, sig
		}
	}
	for i := 0; i < len(p.nonTerminators); i++ {
		if _, ok := symbolUsed[p.nonTerminators[i]]; !ok {
			find(p.nonTerminators[i])
		}
	}
	for i := 0; i < len(p.terminators); i++ {
		if _, ok := symbolUsed[p.terminators[i]]; !ok {
			find(p.terminators[i])
		}
	}
}

func  (p *Parser) FindFollow() {
	p.nonTerminators[0].AddFollow(nil)
	symbolUsed := make(map[*Symbol]bool)
	symbolFollowList := make(map[*Symbol][]*Symbol)
	var addFollow func(dst *Symbol, follow *Symbol)
	addFollow = func(dst *Symbol, follow *Symbol) {
		dst.AddFollow(follow)
		if v, ok := symbolFollowList[dst]; ok && len(v) > 0 {
			for i := 0; i < len(v); i++ {
				addFollow(v[i], follow)
			}
		}
	}
	var find func(s *Symbol)
	find = func(s *Symbol) {
		symbolUsed[s] = true
		symbolFollowList[s] = make([]*Symbol, 0)
		for i := 0; i < len(s.Productions); i++ {
			nowPD := s.Productions[i]
			sig := true
			for j := len(nowPD.Eqs) - 1; j >= 0; j-- {
				if sig {
					for k := 0; k < len(s.Follow); k++ {
						addFollow(nowPD.Eqs[j], s.Follow[k])
					}
					ist := !(s == nowPD.Eqs[j])
					if ist {
						for k := 0; k < len(symbolFollowList[s]); k++ {
							if symbolFollowList[s][k].Cmp(nowPD.Eqs[j]) {
								ist = false
								break
							}
						}
					}
					if ist {
						symbolFollowList[s] = append(symbolFollowList[s], nowPD.Eqs[j])
					}
				}
				if j > 0 {
					sign := false
					for k := 0; k < len(nowPD.Eqs[j].First); k++ {
						if nowPD.Eqs[j].First[k] != nil {
							addFollow(nowPD.Eqs[j-1], nowPD.Eqs[j].First[k])
						} else if sig {
							sign = true
						}
					}
					sig = sign
				}
				if _, ok := symbolUsed[nowPD.Eqs[j]] ;!nowPD.Eqs[j].Type && !ok{find(nowPD.Eqs[j])}
			}
		}
	}
	find(p.nonTerminators[0])
}

func (p *Parser) BuildTable()  {
	statusLen := len(p.status)
	for i := 0; i < statusLen; i++ {
		statusNow := p.status[i]
		p.table.actionTable.table[statusNow] = make(map[*Symbol]*ActionMember)
		p.table.gotoTable.table[statusNow] = make(map[*Symbol]*GotoMember)
		for j := 0; j < len(statusNow.Productions); j++ {
			ReducePD := statusNow.Productions[j].Reduce()
			if ReducePD != nil {
				am := new(ActionMember).New(nil, ReducePD)
				for k := 0; k < len(ReducePD.Sqs.Follow); k++ {
					p.table.actionTable.table[statusNow][ReducePD.Sqs.Follow[k]] = am
				}
			}
		}
		for symbol, status := range statusNow.Next {
			if symbol.Type {
				p.table.actionTable.table[statusNow][symbol] = new(ActionMember).New(status, nil)
			} else {
				p.table.gotoTable.table[statusNow][symbol] = new(GotoMember).New(status)
			}
		}
	}
}

func (p *Parser) Print(w io.Writer) {
	pLen := len(p.productions)
	tLen := len(p.terminators)
	nLen := len(p.nonTerminators)

	for i := 0; i < pLen; i++ {
		fmt.Fprintf(w, "(%d) %s\n", i, p.productions[i].ToString())
	}
	fmt.Fprintf(w, "\n")

	for i := 0; i < tLen; i++ {
		fmt.Fprintf(w, "(%d) %s\n", i, p.terminators[i].Name)
	}
	fmt.Fprintf(w, "\n")

	for i := 0; i < nLen; i++ {
		fmt.Fprintf(w, "(%d) %s\n", i, p.nonTerminators[i].Name)
	}
	fmt.Fprintf(w, "\n")

	for i := 0; i < len(p.nonTerminators); i++ {
		fmt.Fprintf(w,"\t\t%s", p.nonTerminators[i].Name)
	}

	for i := 0; i < len(p.terminators); i++ {
		fmt.Fprintf(w,"\t\t%s", p.terminators[i].Name)
	}
	fmt.Fprintf(w, "\n")

	for i := 0; i < len(p.status); i++ {
		fmt.Fprintf(w, "I%d", i)
		action := p.table.actionTable.table[p.status[i]]
		goto_ := p.table.gotoTable.table[p.status[i]]
		for j := 0; j < len(p.nonTerminators); j++ {
			gm, ok := goto_[p.nonTerminators[j]]
			if ok {
				fmt.Fprintf(w, "%d", p.statusID[gm.status])
			}
		}
		for j := 0; j < len(p.terminators); j++ {
			am, ok := action[p.terminators[j]]
			fmt.Fprintf(w, "\t\t")
			if ok {
				if am.status != nil {
					fmt.Fprintf(w, "s%d", p.statusID[am.status])
				} else {
					fmt.Fprintf(w, "r%d", p.productionsID[am.product])
				}
			}
		}
	}
}

func (p *Parser) Symbol(str string) *Symbol {
	return p.symbolList[str]
}

func (p *Parser) StartStatus() *Status {
	return p.status[0]
}

func (p *Parser) EndStatus() *Status {
	return p.status[1]
}

func (p *Parser) Action() func(status *Status, symbol *Symbol) (*Status, *ProductRule) {
	return func(status *Status, symbol *Symbol) (*Status, *ProductRule) {
		actionMember := p.table.actionTable.table[status][symbol]
		if actionMember == nil {
			return nil, nil
		} else {
			return actionMember.status, actionMember.product
		}
	}
}

func (p *Parser) Goto() func(status *Status, symbol *Symbol) *Status {
	return func(status *Status, symbol *Symbol) *Status {
		gotoMember := p.table.gotoTable.table[status][symbol]
		if gotoMember == nil {
			return nil
		} else {
			return p.table.gotoTable.table[status][symbol].status
		}
	}
}
