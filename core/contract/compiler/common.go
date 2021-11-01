package compiler

import (
	slr1 "github.com/Acoustical/maskash/core/contract/slr"
	"strings"
)

const operators  = "+-*/=><%!;,.()[]"
const numbers = "1234567890"

func OperatorsLike(s rune) bool {
	for i := 0; i < len(operators); i++ {
		if s == rune(operators[i]) {
			return true
		}
	}
	return false
}

func NumberLike(s rune) bool {
	for i := 0; i < len(numbers); i++ {
		if s == rune(numbers[i]) {
			return true
		}
	}
	return false
}

func IsBlank(s rune) bool {
	return s == ' ' || s == '\t'
}

func IsNewLine(s rune) bool {
	return s == '\r' || s == '\n'
}

const productionOfGrammar =
`S -> Start
Start -> mask VersionTotal nextLine Start0
VersionTotal -> Version - Version | Version
Version -> num . num . num | x
Start0 -> cType id Contract
Contract -> start ContractInner end | nextLine
ContractInner -> ContractInner nextLine ContractLine | ContractLine
ContractLine -> VarInit | StructDeclare | FunctionInit | ConstructorInit
VarInit -> Const Type id InitAssign
Const -> const | x
InitAssign -> = Formula | x
Type -> Type => SimpleType | Type [ num ] | SimpleType
SimpleType -> VarType | BaseType | StructType | ( Type )
VarType -> var | privacy var
BaseType -> base | privacy base
StructType -> id
StructDeclare -> struct id Struct
Struct -> start StructInner end | nextLine
StructInner -> StructInner nextLine VarInit | VarInit
FunctionInit -> func FuncAb id ( FunctionInputParams ) FunctionOutputParams Block
ConstructorInit -> constructor ( ) Block
FunctionInputParams -> FunctionInputParams , Type id | Type id | x
FunctionOutputParams ->  ( FunctionOutputParamsInner ) | Type | x
FunctionOutputParamsInner -> FunctionOutputParamsInner , Type | Type
Block -> start FunctionInner end | nextLine
FuncAb -> payable | view | x
FunctionInner -> FunctionInner nextLine Line | Line
Line -> RequireLine | VarInit | EquationLine | SendLine | FromSendLine | IfBlock | ForBlock | continue | break | ReturnLine | TellLine | PublishLine
RequireLine -> require Formula 
EquationLine -> Assignment Eq Formula | Formula
SendLine -> send ArrayInner to SomeBase | send Formula to Assignment
FromSendLine -> from Assignment send Formula to SomeBase | from Assignment send Formula to Assignment
TellLine -> tell Var to SomeBase
PublishLine -> publish Var
IfBlock -> if Formula Block ElifBlock ElseBlock
ElifBlock ->  ElifBlock elif Formula Block | x
ElseBlock -> else Block | x
ForBlock -> for Block | for Formula Block | for Assignment in Formula Block | for Line ; Formula ; Line Block
ReturnLine -> return ArrayInner | return
Eq -> = | + = | - = | * = | / = | >> = | << = | % = | and = |  or =
Assignment -> Assignment . Assignments | Assignments
Assignments -> Assignments [ Formula ] | id
Formula -> F0s | [ ArrayInner ]
ArrayInner ->  ArrayInner , Formula | Formula | x
F0s -> F0s + F1s | F0s - F1s | F1s
F1s -> F1s * F2s | F1s / F2s | F1s % F2s | F2s
F2s -> F2s >> F3s | F2s << F3s | F3s
F3s -> F3s == F4s | F3s > F4s | F3s < F4s | F3s >= F4s | F3s <= F4s | F3s != F4s | F4s
F4s -> F4s in F5s | F5s
F5s -> F5s and F6s | F5s or F6s | F6s
F6s -> ( F0s ) | Assignment | num | boolNum | FunctionCall | - F6s | ( SomeBase ) F6s | ! F6s
SomeBase -> SomeBase , MultiBase | MultiBase
MultiBase -> MultiBase Base | Base
Base -> Formula
FunctionCall -> id ( ArrayInner )
`

var GrammarParser = new(slr1.Parser).New(strings.NewReader(productionOfGrammar))
