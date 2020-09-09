use super::*;

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct EnterpriseAddress {
    pub (crate) network: u8,
    pub (crate) payment: StakeCredential,
}

impl EnterpriseAddress {
    pub fn new(network: u8, payment: &StakeCredential) -> Self {
        Self {
            network,
            payment: payment.clone(),
        }
    }
    pub fn to_address(&self) -> Address {
        Address(AddrType::Enterprise(self.clone()))
    }
}
