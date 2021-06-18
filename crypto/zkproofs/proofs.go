package zkproofs

import "github.com/Acoustical/maskash/crypto"

type ZKProofs interface {
	ProofGen(private *ZKPrivate) (*ZKProofs, error)
	ProofCheck(public *ZKPublic) (bool, error)

	crypto.HashVariable
}

type ZKPublic interface {
	public()
}

type ZKPrivate interface {
	ZKPublic
	private()
}
