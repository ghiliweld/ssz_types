use std::fmt::Debug;
use std::sync::Arc;

use crate::{length::Variable, BitList, BitVector, Bitfield, FixedVector, VariableList};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use typenum::Unsigned;

type ByteVector<N> = FixedVector<u8, N>;
type ByteList<N> = VariableList<u8, N>;
type SignatureBytes = ByteVector<typenum::U96>;
type PublicKeyBytes = ByteVector<typenum::U48>;
type H160 = ByteVector<typenum::U20>;
type H256 = ByteVector<typenum::U32>;
type U256 = FixedVector<u64, typenum::U4>;

#[derive(Clone, PartialEq, Encode, Decode, Debug)]
#[ssz(struct_behaviour = "transparent")]
pub struct CustomBitList<N: Unsigned + Clone>(BitList<N>);

impl<N: typenum::Unsigned + Clone> Default for CustomBitList<N> {
    fn default() -> Self {
        CustomBitList(BitList::with_capacity(0 as usize).unwrap())
    }
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct SignedBeaconBlock {
    pub message: BeaconBlock,
    pub signature: SignatureBytes,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: SignatureBytes,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: H256,
    pub state_root: H256,
    pub body_root: H256,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct BeaconBlock {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: H256,
    pub state_root: H256,
    pub body: BeaconBlockBody,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct BeaconBlockBody {
    pub randao_reveal: SignatureBytes,
    pub eth1_data: Eth1Data,
    pub graffiti: H256,
    pub proposer_slashings: VariableList<ProposerSlashing, typenum::U16>,
    pub attester_slashings: VariableList<AttesterSlashing, typenum::U2>,
    pub attestations: VariableList<Attestation, typenum::U128>,
    pub deposits: VariableList<Deposit, typenum::U16>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, typenum::U16>,
    pub sync_aggregate: SyncAggregate,
    pub execution_payload: ExecutionPayload,
    pub bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, typenum::U16>,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct Eth1Data {
    pub deposit_root: H256,
    pub deposit_count: u64,
    pub block_hash: H256,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct Checkpoint {
    pub epoch: u64,
    pub root: H256,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct AttestationData {
    pub slot: u64,
    pub index: u64,
    pub beacon_block_root: H256,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct IndexedAttestation {
    pub attesting_indices: VariableList<u64, typenum::U2048>,
    pub data: AttestationData,
    pub signature: SignatureBytes,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct AttesterSlashing {
    pub attestation_1: IndexedAttestation,
    pub attestation_2: IndexedAttestation,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct Attestation {
    pub aggregation_bits: CustomBitList<typenum::U2048>,
    pub data: AttestationData,
    pub signature: SignatureBytes,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct DepositData {
    pub pubkey: PublicKeyBytes,
    pub withdrawal_credentials: H256,
    pub amount: u64,
    pub signature: SignatureBytes,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct Deposit {
    pub proof: FixedVector<H256, typenum::U32>,
    pub data: DepositData,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct VoluntaryExit {
    pub epoch: u64,
    pub validator_index: u64,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: SignatureBytes,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct SyncAggregate {
    pub sync_committee_bits: BitVector<typenum::U512>,
    pub sync_committee_signature: SignatureBytes,
}

pub type Transaction = ByteList<typenum::U1073741824>;

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: H160,
    pub amount: u64,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct ExecutionPayload {
    pub parent_hash: H256,
    pub fee_recipient: H160,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: ByteVector<typenum::U256>,
    pub prev_randao: H256,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    // TODO(Grandine Team): Try removing the `Arc` when we have data for benchmarking Bellatrix.
    //                      The cost of cloning `ByteList<MaxExtraDataBytes>` may be negligible.
    pub extra_data: Arc<ByteList<typenum::U32>>,
    pub base_fee_per_gas: U256,
    pub block_hash: H256,
    // TODO(Grandine Team): Consider removing the `Arc`. It can be removed with no loss of performance
    //                      at the cost of making `ExecutionPayloadV1` more complicated.
    pub transactions: Arc<VariableList<Transaction, typenum::U1048576>>,
    pub withdrawals: VariableList<Withdrawal, typenum::U16>,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct SignedBlsToExecutionChange {
    pub message: BlsToExecutionChange,
    pub signature: SignatureBytes,
}

#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
#[ssz(struct_behaviour = "container")]
pub struct BlsToExecutionChange {
    pub validator_index: u64,
    pub from_bls_pubkey: PublicKeyBytes,
    pub to_execution_address: H160,
}
