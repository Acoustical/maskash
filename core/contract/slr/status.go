package slr1

type RawStatus struct {
	opening []*ProductRule
}

func (rs *RawStatus) New(p []*ProductRule) *RawStatus {
	rs.opening = p
	return rs
}

func (rs *RawStatus) GenStatus() *Status {
	return new(Status).New(rs)
}

type Status struct {
	Closure int
	Productions []*ProductRule
	Next map[*Symbol]*Status
}

func (st *Status) New(r *RawStatus) *Status {
	st.Closure = len(r.opening)
	used := make(map[*Symbol]bool)
	var InsertProduction func([]*ProductRule)
	InsertProduction = func(products []*ProductRule) {
		pLen := len(products)
		if pLen == 0 {return}
		st.Productions = append(st.Productions, products...)
		newProducts := make([]*ProductRule, 0)
		for i := 0; i < pLen; i++ {
			symbolProcessing := products[i].NextSymbol()
			if symbolProcessing != nil {
				_, ok := used[symbolProcessing]
				if !ok {
					used[symbolProcessing] = true
					symbolProcessing.ForEveryProduct(func(p *ProductRule) {
						newProducts = append(newProducts, p.ExportToPrefix())
					})
				}
			}
		}
		InsertProduction(newProducts)
	}
	InsertProduction(r.opening)
	st.Next = make(map[*Symbol]*Status)
	return st
}

func (st *Status) Cmp(sta *Status) bool {
	if st.Closure != sta.Closure {
		return false
	} else {
		for i := 0; i < st.Closure; i++ {
			if !st.Productions[i].Cmp(sta.Productions[i]) {
				return false
			}
		}
		return true
	}
}

func (st *Status) CmpRaw(rs *RawStatus) bool {
	oLen := len(rs.opening)
	if st.Closure != oLen {
		return false
	} else {
		for i := 0; i < st.Closure; i++ {
			if !st.Productions[i].Cmp(rs.opening[i]) {
				return false
			}
		}
		return true
	}
}

func (st *Status) NextStatus() ([]*Symbol, []*RawStatus) {
	rawStatus := make([]*RawStatus, 0)
	symbols := make([]*Symbol, 0)
	used := make(map[*ProductRule]bool)
	Len := len(st.Productions)
	for i := 0; i < Len; i++ {
		p := st.Productions[i]
		newP := make([]*ProductRule, 0)
		_, ok := used[p]
		if !ok {
			used[p] = true
			sb := p.NextSymbol()
			if sb != nil {
				for j := i; j < Len; j++ {
					raw := st.Productions[j].Next(sb)
					if raw != nil {
						newP = append(newP, raw)
					}
				}
				symbols = append(symbols, sb)
				rawStatus = append(rawStatus, new(RawStatus).New(newP))
			}
		}
	}
	return symbols, rawStatus
}

func (st *Status) ToString() string {
	str := "| {"
	for i := 0; i < len(st.Productions); i++ {
		str += "\n|\t" + st.Productions[i].ToString()
	}
	str += "\n| }"
	return str
}
