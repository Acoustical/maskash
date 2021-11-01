package slr1

type LRTable struct {
	actionTable *ActionTable
	gotoTable *GotoTable
}

func (table *LRTable) New() *LRTable {
	table.actionTable = new(ActionTable).New()
	table.gotoTable = new(GotoTable).New()
	return table
}

type ActionTable struct {
	table map[*Status]map[*Symbol]*ActionMember
}

func (at *ActionTable) New() *ActionTable {
	at.table = make(map[*Status]map[*Symbol]*ActionMember)
	return at
}

type ActionMember struct {
	status *Status
	product *ProductRule
}

func (am *ActionMember) New(status *Status, product *ProductRule) *ActionMember {
	am.status, am.product = status, product
	return am
}

type GotoTable struct {
	table map[*Status]map[*Symbol]*GotoMember
}

func (gt *GotoTable) New() *GotoTable {
	gt.table = make(map[*Status]map[*Symbol]*GotoMember)
	return gt
}

type GotoMember struct {
	status *Status
}

func (gm *GotoMember) New(status *Status) *GotoMember {
	gm.status = status
	return gm
}