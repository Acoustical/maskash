package slr1

type Symbol struct {
	Type bool
	Name string
	First []*Symbol
	Follow []*Symbol
	Productions []*ProductRule
}

func (s *Symbol) New(str string) *Symbol {
	if str == "x" {
		return nil
	}
	s.Type = str[0] < 'A' || str[0] > 'Z'
	s.Name = str
	s.First = make([]*Symbol, 0)
	s.Follow = make([]*Symbol, 0)
	s.Productions = make([]*ProductRule, 0)
	return s
}

func (s *Symbol) Cmp(cp *Symbol) bool {
	if s == nil && cp == nil {
		return true
	} else if s == nil || cp == nil {
		return false
	} else {
		return s.Name == cp.Name
	}
}

func (s *Symbol) AddFirst(fl *Symbol) {
	for _, symbol := range s.First {
		if symbol.Cmp(fl) {
			return
		}
	}
	s.First = append(s.First, fl)
}

func (s *Symbol) AddFollow(fl *Symbol) {
	for _, symbol := range s.Follow {
		if symbol.Cmp(fl) {
			return
		}
	}
	s.Follow = append(s.Follow, fl)
}

func (s *Symbol) IsFirst(fl *Symbol) bool {
	for i := 0; i < len(s.First); i++ {
		if fl.Cmp(s.First[i]){
			return true
		}
	}
	return false
}

func (s *Symbol) IsFollow(fl *Symbol) bool {
	for i := 0; i < len(s.Follow); i++ {
		if fl.Cmp(s.Follow[i]){
			return true
		}
	}
	return false
}

func (s *Symbol) ForEveryFollow(f func(s *Symbol)) {
	for i := 0; i < len(s.Follow); i++ {
		f(s.Follow[i])
	}
}

func (s *Symbol) AddProduct(p *ProductRule) {
	s.Productions = append(s.Productions, p)
}

func (s *Symbol) ForEveryProduct(f func(p *ProductRule)) {
	for i := 0; i < len(s.Productions); i++ {
		f(s.Productions[i])
	}
}
