package zkproofs

import "github.com/Acoustical/maskash/crypto"

type ZK interface {
	ZKProof
	ZKPrivate

	Proof() error
	Check() bool
	SetBytes(b []byte) error
}

type ZKProof interface {
	crypto.HashVariable
}

type ZKPublic interface {
	public()
}

type ZKPrivate interface {
	ZKPublic
	private()
}
