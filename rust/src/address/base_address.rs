use super::*;

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct BaseAddress {
    pub (crate) network: u8,
    pub (crate) payment: StakeCredential,
    pub (crate) stake: StakeCredential,
}

impl BaseAddress {
    pub fn new(network: u8, payment: &StakeCredential, stake: &StakeCredential) -> Self {
        Self {
            network,
            payment: payment.clone(),
            stake: stake.clone(),
        }
    }
    pub fn to_address(&self) -> Address {
        Address(AddrType::Base(self.clone()))
    }
}
