package slr1

type ProductRule struct {
	Type bool
	Sqs *Symbol
	Eqs []*Symbol
	prefix int
	origin *ProductRule
}

func (p *ProductRule) New(Sqs *Symbol, Eqs []*Symbol) *ProductRule {
	p.Type = false
	p.Sqs = Sqs
	p.Eqs = Eqs
	p.prefix = 0
	p.origin = nil
	return p
}

func (p *ProductRule) Cmp(pc *ProductRule) bool {
	if p.Type != pc.Type {
		return false
	} else if p.Type == true && p.prefix != pc.prefix {
		return false
	} else if !p.Sqs.Cmp(pc.Sqs) {
		return false
	} else if len(p.Eqs) != len(pc.Eqs) {
		return false
	} else {
		for i := 0; i < len(p.Eqs); i++ {
			if !p.Eqs[i].Cmp(pc.Eqs[i]) {
				return false
			}
		}
		return true
	}
}

func (p *ProductRule) ExportToPrefix() *ProductRule {
	pe := new(ProductRule)
	pe.Type = true
	pe.Sqs = p.Sqs
	pe.Eqs = p.Eqs
	pe.prefix = 0
	pe.origin = p
	return pe
}

func (p *ProductRule) Next(s *Symbol) *ProductRule {
	if p.Type == true && len(p.Eqs) > p.prefix && p.NextSymbol().Cmp(s) {
		pe := new(ProductRule)
		pe.Type = true
		pe.Sqs = p.Sqs
		pe.Eqs = p.Eqs
		pe.prefix = p.prefix+1
		pe.origin = p.origin
		return pe
	} else {
		return nil
	}
}

func (p *ProductRule) NextSymbol() *Symbol {
	if p.Type == true && len(p.Eqs) > p.prefix {
		return p.Eqs[p.prefix]
	} else {
		return nil
	}
}

func (p *ProductRule) Reduce() *ProductRule {
	if p.Type && p.prefix == len(p.Eqs) {
		return p.origin
	} else {
		return nil
	}
}

func (p *ProductRule) ToString() string {
	str := p.Sqs.Name + " ->"
	for i := 0; i < len(p.Eqs) + 1; i++ {
		if i == p.prefix && p.Type {
			str += " ."
		}
		if i < len(p.Eqs) {
			str += " " + p.Eqs[i].Name
		}
	}
	return str
}


