pub mod chain_crypto;
pub mod crypto;
pub mod address;

type Epoch = u32;
type Slot = u32;
// index of a tx within a block
type TransactionIndex = u32;
// index of a cert within a tx
type CertificateIndex = u32;
