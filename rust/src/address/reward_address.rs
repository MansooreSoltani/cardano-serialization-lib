use super::*;

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RewardAddress {
    pub (crate) network: u8,
    pub (crate) payment: StakeCredential,
}

impl RewardAddress {
    pub fn new(network: u8, payment: &StakeCredential) -> Self {
        Self {
            network,
            payment: payment.clone(),
        }
    }

    pub fn to_address(&self) -> Address {
        Address(AddrType::Reward(self.clone()))
    }
}