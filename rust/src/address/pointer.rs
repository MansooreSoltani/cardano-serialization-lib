use crate::{Slot, TransactionIndex, CertificateIndex};

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Pointer {
    pub (crate) slot: Slot,
    pub (crate) tx_index: TransactionIndex,
    pub (crate) cert_index: CertificateIndex,
}

impl Pointer {
    pub fn new(slot: Slot, tx_index: TransactionIndex, cert_index: CertificateIndex) -> Self {
        Self {
            slot,
            tx_index,
            cert_index,
        }
    }

    pub fn slot(&self) -> Slot {
        self.slot.clone()
    }

    pub fn tx_index(&self) -> TransactionIndex {
        self.tx_index.clone()
    }

    pub fn cert_index(&self) -> CertificateIndex {
        self.cert_index.clone()
    }
}
