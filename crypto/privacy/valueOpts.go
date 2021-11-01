package privacy

import (
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/crypto/zkproofs"
	"github.com/Acoustical/maskash/errors"
	"math/big"
)

func Add(aux *AuxiliaryVariables, v ...Value) (Value, error) {
	zero := big.NewInt(0)
	one := big.NewInt(1)
	ngOne := big.NewInt(-1)
	plaintextSum := big.NewInt(0)
	secret := make([]*SecretValue, 0)
	anonymous := make([]*AnonymousValue, 0)
	solvable := true
	vLen := len(v)
	for i := 0; i < vLen; i++ {
		switch v_ := v[i].(type) {
		case *PlaintextValue:
			plaintextSum.Add(plaintextSum, v_.v)
		case *SecretValue:
			secret = append(secret, v_)
			if !v_.Solvable() {solvable = false}
		case *AnonymousValue:
			anonymous = append(anonymous, v_)
			if !v_.Solvable() {solvable = false}
		}
	}
	secretLen := len(secret)
	anonymousLen := len(anonymous)
	if aux.Match(0,0,0) {
		if anonymousLen > 0 {
			return nil, errors.NewAuxiliarySizeNotMatchError()
		}
		if vLen == 0 {return &PlaintextValue{zero}, nil}
		if vLen == 1 {return v[0], nil}
		if secretLen > 0 {
			var d *crypto.Commitment
			c := new(crypto.Commitment).SetInt(plaintextSum)
			if solvable {d = new(crypto.Commitment).SetInt(zero)}
			for _, s := range secret {
				c.AddBy(s.c)
				if solvable {d.AddBy(s.d)}
			}
			return &SecretValue{c, d}, nil
		} else {
			return &PlaintextValue{plaintextSum}, nil
		}
	} else if aux.Match(1,0,0) {
		if anonymousLen == 0 || secretLen > 0 {
			return nil, errors.NewAuxiliarySizeNotMatchError()
		}
		base_ := aux.Bases[0]
		base, ok := base_.(*AnonymousBase)
		if !ok {return nil, errors.NewAuxiliaryTypeNotMatchError(base_)}
		if vLen == 1 {return v[0], nil}
		var d *crypto.Commitment
		c := new(crypto.Commitment).SetIntByGenerator(base.g, plaintextSum)
		if solvable {d = new(crypto.Commitment).SetInt(zero)}
		for _, s := range secret {
			c.AddBy(s.c)
			if solvable {d.AddBy(s.d)}
		}
		return &AnonymousValue{c, d}, nil
	} else if (aux.Match(secretLen+anonymousLen+1, 1, 1) && !aux.Values[0].Solvable()) || (aux.Match(secretLen+anonymousLen+1, 1, 2) && aux.Values[0].Solvable()) {
		A := make([]*big.Int, 0)
		G := make([]*crypto.Generator, 0)
		B := new(big.Int).Neg(plaintextSum)
		Y := new(crypto.Commitment).SetInt(zero)

		for i := 0; i < secretLen+anonymousLen; i++ {
			if i < secretLen {
				bs, ok := aux.Bases[i].(*SecretBase)
				if !ok {return nil, errors.NewAuxiliaryTypeNotMatchError(aux.Bases[i])}
				if i == 0 {
					A = append(A, one)
					G = append(G, new(crypto.Generator).Init(one))
				}
				for j := 1; j < len(G); j++ {
					if bs.h.Cmp(G[j]) {break}
					if j == len(G)-1 {
						A = append(A, zero)
						G = append(G, bs.h)
					}
				}
				Y.AddBy(secret[i].c)
			} else {
				bs, ok := aux.Bases[i].(*AnonymousBase)
				if !ok {return nil, errors.NewAuxiliaryTypeNotMatchError(aux.Bases[i])}
				for j := secretLen; j < len(G); j+=2 {
					if bs.g.Cmp(G[j]) &&  bs.h.Cmp(G[j+1]) {
						A = append(A, one, zero)
						G = append(G, bs.g, bs.h)
					}
				}
				Y.AddBy(anonymous[i-secretLen].c)
			}
		}
		var g, h *crypto.Generator
		var c1, c2 *crypto.Commitment
		switch c := aux.Values[0].(type) {
		case *PlaintextValue:
			_, ok := aux.Bases[secretLen+anonymousLen].(*PlaintextBase)
			if !ok {return nil, errors.NewAuxiliaryTypeNotMatchError(aux.Bases[secretLen+anonymousLen])}
			B.Add(B, c.v)
		case *SecretValue:
			bs, ok := aux.Bases[secretLen+anonymousLen].(*SecretBase)
			if !ok {return nil, errors.NewAuxiliaryTypeNotMatchError(aux.Bases[secretLen+anonymousLen])}
			g, h = new(crypto.Generator).Init(one), bs.h
			c1, c2 = c.c, c.d
			if secretLen == 0 {
				A = append(A, ngOne, zero)
				G = append(G, g, h)
				Y.AddBy(c.c)
			} else {
				for i := 0; i < secretLen; i++ {
					bss := aux.Bases[i].(*SecretBase)
					if bss.h.Cmp(h) {
						Y.SubBy(c.c)
						break
					}
					if i == secretLen-1 {
						A = append(A, zero)
						G = append(G, h)
						Y.SubBy(c.c)
					}
				}
			}
		case *AnonymousValue:
			bs, ok := aux.Bases[secretLen+anonymousLen].(*AnonymousBase)
			if !ok {return nil, errors.NewAuxiliaryTypeNotMatchError(aux.Bases[secretLen+anonymousLen])}
			g, h = bs.g, bs.h
			c1, c2 = c.c, c.d
			for i := 0; i < anonymousLen; i++ {
				bss := aux.Bases[secretLen+i].(*AnonymousBase)
				if bss.g.Cmp(g) && bss.h.Cmp(h) {
					Y.SubBy(c.c)
					break
				}
				if i == secretLen-1 {
					A = append(A, ngOne, zero)
					G = append(G, g, h)
					Y.AddBy(c.c)
				}
			}
		}
		linearZK, ok := aux.ZKs[0].(*zkproofs.LinearEquationZK)
		if !ok {return nil, errors.NewAuxiliaryTypeNotMatchError(aux.ZKs[0])}
		_, err := linearZK.SetPublic(A, B, Y, G)
		if err != nil {return nil, err}
		if !linearZK.Check() {return nil, errors.NewZKCheckNotPassError()}
		if aux.Match(secretLen+anonymousLen+1, 1, 2) {
			formatZK, ok := aux.ZKs[1].(*zkproofs.FormatZK)
			if !ok {return nil, errors.NewAuxiliaryTypeNotMatchError(aux.ZKs[1])}
			formatZK.SetPublic(g, h, c1, c2)
			if !formatZK.Check() {return nil, errors.NewZKCheckNotPassError()}
		}
		return aux.Values[0], nil
	} else {
		return nil, errors.NewAuxiliarySizeNotMatchError()
	}
}

/*
func GenAddAuxiliary(b []Base, v, r []*big.Int, answerBase Base, solvable bool) (*AuxiliaryVariables, *big.Int, *big.Int, error) {
	bLen, vLen, rLen := len(b), len(v), len(r)
	if bLen != vLen {return nil, nil, nil, errors.NewLengthNotMatchError(bLen, vLen)}
	if bLen != rLen {return nil, nil, nil, errors.NewLengthNotMatchError(bLen, rLen)}
	if bLen < 2 {return nil, nil, nil, errors.NewWrongInputLength(bLen)}
	
	pBases, sBases, aBases := make([]*PlaintextBase, 0), make([]*SecretBase, 0), make([]*AnonymousBase, 0)
	for i := 0; i < bLen; i++ {
		switch bs := b[i].(type) {
		case *PlaintextBase:

		case *SecretBase:

		case *AnonymousBase:

		}
	}
}
 */


