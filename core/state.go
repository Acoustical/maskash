package core

import (
	"github.com/Acoustical/maskash/crypto"
	"github.com/Acoustical/maskash/crypto/privacy"
	"sort"
)

type TrieRoot struct {
	hash crypto.Hash
	child map[byte]*TrieRoot
	leaf *trieLeaf
}

type trieLeaf struct {
	IsUTXO bool
	value privacy.Value
}

func (root *TrieRoot) updateHash()  {
	if root.child == nil {
		root.hash = crypto.Hash_(root.leaf.value)
	}
	childLen := len(root.child)
	if childLen == 1 {
		for _, v := range root.child {copy(root.hash[:], v.hash[:])}
	} else {
		var keys trieKey = make([]byte, 0, childLen)
		hashes := make([]crypto.HashVariable, 0, childLen)
		for k := range root.child {
			keys = append(keys, k)
		}
		sort.Sort(keys)
		for i := 0; i < childLen; i++ {hashes[i] = root.child[keys[i]].hash}
		root.hash = crypto.Hash_(hashes...)
	}
}

func (root *TrieRoot) Set(b []byte, v privacy.Value, utxo bool)  {
	bLen := len(b)
	r := root
	tList := make([]*TrieRoot, 0, bLen + 1)
	tList = append(tList, r)
	for i := 0; i < bLen; i++ {
		if r.child == nil {r.child = make(map[byte]*TrieRoot)}
		k := b[i]
		s, ok := r.child[k]
		if !ok {
			s = new(TrieRoot)
			r.child[k] = s
		}
		r = s
		tList = append(tList, r)
	}
	r.leaf = &trieLeaf{utxo, v}
	for i := bLen; i >= 0; i-- {tList[i].updateHash()}
}

func (root *TrieRoot) Get(b []byte) (privacy.Value, bool) {
	bLen := len(b)
	r := root
	for i := 0; i < bLen; i++ {
		if r.child == nil {r.child = make(map[byte]*TrieRoot)}
		k := b[i]
		s, ok := r.child[k]
		if !ok {
			s = new(TrieRoot)
			r.child[k] = s
		}
		r = s
	}
	return r.leaf.value, r.leaf.IsUTXO
}

func (root *TrieRoot) Delete(b []byte) {
	bLen := len(b)
	r := root
	tList := make([]*TrieRoot, 0, bLen)
	tList = append(tList, r)
	for i := 0; i < bLen - 1; i++ {
		if r.child == nil {r.child = make(map[byte]*TrieRoot)}
		k := b[i]
		r = r.child[k]
		tList = append(tList, r)
	}
	delete(r.child, b[bLen-1])
	for i := bLen; i >= 0; i-- {tList[i].updateHash()}
}

type trieKey []byte

func (k trieKey) Len() int {return len(k)}

func (k trieKey) Less(i, j int) bool {return k[i] < k[j]}

func (k trieKey) Swap(i, j int)  {k[i], k[j] = k[j], k[i]}

func (root *TrieRoot) SetUserBalance(base privacy.Base, value privacy.Value) {

}

func (root *TrieRoot) SetContractValue(contract privacy.Base, name string, value privacy.Value)  {

}
