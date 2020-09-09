use super::*;

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct PointerAddress {
    pub (crate) network: u8,
    pub (crate) payment: StakeCredential,
    pub (crate) stake: Pointer,
}

impl PointerAddress {
    pub fn new(network: u8, payment: &StakeCredential, stake: &Pointer) -> Self {
        Self {
            network,
            payment: payment.clone(),
            stake: stake.clone(),
        }
    }

    pub fn to_address(&self) -> Address {
        Address(AddrType::Ptr(self.clone()))
    }
}