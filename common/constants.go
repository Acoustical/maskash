package common

const ByteBits int = 8
const Bn256ZqBits int = 256
const Bn256PointBits int = 256 + 8

const RangeProofShortBits int = 20
const RangeProofLongBits int = 40
const MaxShortValue int = 1 << RangeProofShortBits - 1
const MaxLongValue int = 1 << RangeProofLongBits - 1

const FormatProofLength = 3 * Bn256ZqBits / ByteBits
const RangeProofShortLength = (4 * Bn256PointBits + (2 + 2 * RangeProofShortBits) * Bn256ZqBits) / ByteBits

const PlaintextBaseLength int = 20
const PlaintextInputValueLength = 2 * Bn256ZqBits / ByteBits
const PlaintextOutputValueLength = Bn256ZqBits / ByteBits
const PlaintextZKsLength = (Bn256PointBits + Bn256ZqBits) / ByteBits
const PlaintextInputSlotLength = 1 + PlaintextBaseLength + PlaintextInputValueLength + PlaintextZKsLength
const PlaintextOutputSlotLength = 1 + PlaintextBaseLength + PlaintextOutputValueLength

const SecretBaseLength = Bn256PointBits / ByteBits
const SecretSolvableValueLength = 2 * Bn256PointBits / ByteBits
const SecretNonSolvableValueLength = Bn256PointBits / ByteBits
const SecretZKsLength = FormatProofLength + RangeProofShortLength
const SecretInputSolvableSlotLength = 1 + SecretBaseLength + SecretSolvableValueLength
const SecretInputNonSolvableSlotLength = 1 + SecretBaseLength + SecretNonSolvableValueLength
const SecretOutputSolvableSlotLength = 1 + SecretBaseLength + SecretSolvableValueLength + SecretZKsLength
const SecretOutputNonSolvableSlotLength = 1 + SecretBaseLength + SecretNonSolvableValueLength + SecretZKsLength

const AnonymousBaseLength = 2 * Bn256PointBits / ByteBits
const AnonymousSolvableValueLength = 2 * Bn256PointBits / ByteBits
const AnonymousNonSolvableValueLength = Bn256PointBits / ByteBits
const AnonymousZKsLength = FormatProofLength + RangeProofShortLength
const AnonymousInputSolvableSlotLength = 1 + AnonymousBaseLength + AnonymousSolvableValueLength
const AnonymousInputNonSolvableSlotLength = 1 + AnonymousBaseLength + AnonymousNonSolvableValueLength
const AnonymousOutputSolvableSlotLength = 1 + AnonymousBaseLength + AnonymousSolvableValueLength + AnonymousZKsLength
const AnonymousOutputNonSolvableSlotLength = 1 + AnonymousBaseLength + AnonymousNonSolvableValueLength + AnonymousZKsLength

const PrivacyMode uint8 = 0b11000000
const Plaintext uint8 = 0b00000000
const Secret uint8 = 0b01000000
const Anonymous uint8 = 0b10000000
const Obscure uint8 = 0b11000000

const ContractSlotMode uint8 = 0b00110000
const NoneContractSlot uint8 = 0b00000000
const ContractCreation uint8 = 0b00010000
const ContractCall uint8 = 0b00100000
const ContractReceipt uint8 = 0b00110000

const TxSlotKind uint8 = 0b00001000
const InputSlot uint8 = 0b00000000
const OutputSlot uint8 = 0b00001000

const Solvability uint8 = 0b00000100
const Solvable uint8 = 0b00000100
const NonSolvable uint8 = 0b00000000

const IsGasSlot uint8 = 0b00000011


