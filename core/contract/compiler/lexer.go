package compiler

import (
	"bufio"
	slr1 "github.com/Acoustical/maskash/core/contract/slr"
	"github.com/Acoustical/maskash/errors"
	"io"
	"os"
	"strconv"
)

type LetterNode struct {
	typ *slr1.Symbol
	value *int
	location [2]uint
	next *LetterNode
}

func (l *LetterNode) New(typ *slr1.Symbol, v *int, location [2]uint) *LetterNode {
	l.typ = typ
	l.value = v
	l.location = location
	return l
}

func (l *LetterNode) NewOperator(str string, location [2]uint) *LetterNode {
	return l.New(GrammarParser.Symbol(str), nil, location)
}

func (l *LetterNode) NewIDLike(str string, idList []string, location [2]uint) (*LetterNode, []string) {
	zero := 0
	one := 1
	two := 2
	three := 3
	four := 128
	switch str {
	case "MASK":
		return l.New(GrammarParser.Symbol("mask"), nil, location), idList
	case "true":
		return l.New(GrammarParser.Symbol("boolNum"), &one, location), idList
	case "false":
		return l.New(GrammarParser.Symbol("boolNum"), &zero, location), idList
	case "knowledge":
		return l.New(GrammarParser.Symbol("id"), &zero, location), idList
	case "msg":
		return l.New(GrammarParser.Symbol("id"), &one, location), idList
	case "sender":
		return l.New(GrammarParser.Symbol("id"), &two, location), idList
	case "receiver":
		return l.New(GrammarParser.Symbol("id"), &three, location), idList
	case "public":
		return l.New(GrammarParser.Symbol("cType"), &zero, location), idList
	case "private":
		return l.New(GrammarParser.Symbol("cType"), &one, location), idList
	case "plaintext":
		return l.New(GrammarParser.Symbol("privacy"), &zero, location), idList
	case "secret":
		return l.New(GrammarParser.Symbol("privacy"), &one, location), idList
	case "anonymous":
		return l.New(GrammarParser.Symbol("privacy"), &two, location), idList
	case "int":
		return l.New(GrammarParser.Symbol("var"), &zero, location), idList
	case "bool":
		return l.New(GrammarParser.Symbol("var"), &three, location), idList
	case "balance":
		return l.New(GrammarParser.Symbol("var"), &four, location), idList
	default:
		syb := GrammarParser.Symbol(str)
		if syb == nil {
			idLen := len(idList)
			for i := 0; i < idLen; i++ {
				if str == idList[i] {
					x := i+4
					return l.New(GrammarParser.Symbol("id"), &x, location), idList
				}
			}
			x := idLen+4
			idList = append(idList, str)
			return l.New(GrammarParser.Symbol("id"), &x, location), idList
		} else {
			return l.New(syb, nil, location), idList
		}
	}
}

func (l *LetterNode) NewNum(str string, location [2]uint) *LetterNode {
	num64, _ := strconv.ParseInt(str, 0, 64)
	num := int(num64)
	return l.New(GrammarParser.Symbol("num"), &num, location)
}

func NewLine(str string, prv *int, sg string, location [2]uint) ([]*LetterNode, Error) {
	num := 0
	sgLen := len(sg)
	for i := 0; i < len(str); i++ {
		if str[i] != sg[i%sgLen] {
			return nil, new(WrongIndentError).New(location)
		} else if (i+1)%sgLen == 0 {
			num += 1
		} else if i == len(str) - 1 {
			return nil, new(WrongIndentError).New(location)
		}
	}
	if num - *prv == 1 {
		*prv = num
		rt := make([]*LetterNode, 1)
		rt[0] = new(LetterNode).New(GrammarParser.Symbol("start"), nil, location)
		return rt, nil
	} else if num - *prv < 0 {
		rt := make([]*LetterNode, *prv-num+1)
		for i := 0; i < *prv-num; i++ {
			rt[i] = new(LetterNode).New(GrammarParser.Symbol("end"), nil, location)
		}
		rt[*prv-num] = new(LetterNode).New(GrammarParser.Symbol("nextLine"), nil, location)
		*prv = num
		return rt, nil
	} else if num == *prv {
		rt := make([]*LetterNode, 1)
		rt[0] = new(LetterNode).New(GrammarParser.Symbol("nextLine"), nil, location)
		return rt, nil
	} else {
		return nil, new(WrongIndentError).New(location)
	}
}

type LetterChain struct {
	head *LetterNode
}

func (lc *LetterChain) InitFromFile(filename string) *LetterChain {
	file, err := os.Open(filename)
	errors.Handle(err)
	fileReader := bufio.NewReader(file)
	now, _, err := fileReader.ReadRune()
	var next rune
	idList := make([]string, 0)
	newLineSymbol := "x"
	newLineBuffer := "x"
	lc.head = new(LetterNode)
	r := lc.head
	nowLine := new(int)
	*nowLine = 0

	buffer := ""
	var nowType uint8 = 0
	location := [2]uint{0, 0}

	newLineFunction := func(location [2]uint) {
		if newLineBuffer != "x" {
			if newLineSymbol == "x" && newLineBuffer != ""{
				newLineSymbol = newLineBuffer
			}
			rt, err_ := NewLine(newLineBuffer,nowLine,newLineSymbol,location)
			if err_ != nil {Alert(err_)}
			for i := 0; i < len(rt); i++ {
				r.next = rt[i]
				r = r.next
			}
			newLineBuffer = "x"
		}
	}

	newOperatorFunction := func() {
		r.next = new(LetterNode).NewOperator(buffer, location)
		r = r.next
		buffer = ""
		nowType = 0
	}

	newIDFunction := func() {
		r.next, idList = new(LetterNode).NewIDLike(buffer, idList, location)
		r = r.next
		buffer = ""
		nowType = 0
	}

	newNumFunction := func() {
		r.next = new(LetterNode).NewNum(buffer, location)
		r = r.next
		buffer = ""
		nowType = 0
	}

	for err != io.EOF {
		if nowType == 0 {
			if !IsBlank(now) {
				if OperatorsLike(now) {
					nowType = 1
				} else if NumberLike(now) {
					nowType = 2
				} else if IsNewLine(now){
					nowType = 3
				} else {
					nowType = 4
				}
				if nowType != 3 {
					buffer += string(now)
				}
			}
		}
		next, _, err = fileReader.ReadRune()
		switch nowType {
		case 0:
		case 1:
			if len(buffer) == 2 && ( buffer != "//" && buffer != "/*" )||
				buffer == "+" ||
				buffer == "-" ||
				buffer == "*" ||
				buffer == "/"  && ( next != '/' && next != '*')||
				buffer == "%"  ||
				buffer == ";" ||
				buffer == ","  ||
				buffer == "." ||
				buffer == "(" ||
				buffer == ")" ||
				buffer == "[" ||
				buffer == "]" ||
				buffer == "=" && ( next != '=' && next != '>') ||
				buffer == ">" && ( next != '=' && next != '>') ||
				buffer == "<" && ( next != '=' && next != '<') ||
				buffer == "!" && next != '=' {

				newLineFunction(location)
				newOperatorFunction()

			} else if buffer == "//" {
				buffer = ""
				nowType = 5
			} else if buffer == "/*" {
				buffer = ""
				nowType = 6
			} else {
				buffer += string(next)
			}
		case 2:
			if NumberLike(next) || (buffer == "0" && next == 'x') {
				buffer += string(next)
			} else if OperatorsLike(next) || IsBlank(next) || IsNewLine(next) {
				newLineFunction(location)
				newNumFunction()
			}
		case 3:
			if IsNewLine(next) {
				if next == '\n' {
					buffer = ""
				}
			} else if IsBlank(next) {
				buffer += string(next)
			} else {
				newLineBuffer = buffer
				nowType = 0
				buffer = ""
			}
		case 4:
			if OperatorsLike(next) || NumberLike(next) || IsBlank(next) || IsNewLine(next) {
				newLineFunction(location)
				newIDFunction()
			} else {
				buffer += string(next)
			}
		case 5:
			if next == '\n' {
				nowType = 3
				if newLineBuffer != "x" {
					newLineBuffer = "x"
				}
			}
		case 6:
			if buffer == "" && next == '*' {
				buffer = "*"
			} else if buffer == "*" && next == '/' {
				buffer = "*/"
			} else if buffer == "*/" {
				if newLineBuffer != "x" {
					newLineBuffer = "x"
				}
				buffer = ""
				nowType = 0
			}
		}
		if now == '\n' {
			location[0]++
			location[1] = 0
		} else {
			location[1] ++
		}
		now = next
	}
	for i := 0; i < *nowLine; i++ {
		r.next = new(LetterNode).New(GrammarParser.Symbol("end"), nil, location)
		r = r.next
	}
	r = &LetterNode{nil, nil, location, nil}
	//r.next = new(LetterNode).New(GrammarParser.Symbol("nextLine"), nil)
	return lc
}







