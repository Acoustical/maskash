package compiler

// TODO : 不用去考虑值，只考虑具体判断对比，只关心怎么生成中间代码，判断类型是否合理，变量是否声明等

type IDMap map[string]*ID
type StructDeclareList map[string]int

type ContractMaps struct {
	cMap *CompilingMaps
	structs StructDeclareList
}

type CompilingMaps struct {
	idMap IDMap
	parents *CompilingMaps
}

func (cm *CompilingMaps) New(parents *CompilingMaps) *CompilingMaps {
	cm.idMap = make(IDMap)
	cm.parents = parents
	return cm
}

type ID struct {
	defined [2]uint
	typ byte
	mTyp *int
	privacy byte
	value []byte
}

func (id *ID) New(typ byte, mTyp *int, privacy byte, value []byte) *ID {
	id.typ = typ
	id.mTyp = mTyp
	id.privacy = privacy
	id.value = value
	return id
}

func (idMap IDMap) Define(typ byte, mTyp *int, privacy byte, value []byte, name string, location [2]uint) (*ID, Error) {
	if id, ok := idMap[name]; ok {
		if id.defined == [2]uint{0, 0} {
			id.defined = location
			return id, nil
		} else {
			return nil, new(DuplicateDefinedError).New(location, name)
		}
	} else {
		idMap[name] = new(ID).New(typ, mTyp, privacy, value)
		idMap[name].defined = location
		return idMap[name], nil
	}
}


