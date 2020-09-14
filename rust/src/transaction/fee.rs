use crate::Coin;
use crate::transaction::Transaction;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LinearFee {
    constant: Coin,
    coefficient: Coin,
}

impl LinearFee {
    pub fn new(coefficient: &Coin, constant: &Coin) -> Self {
        Self {
            constant: constant.clone(),
            coefficient: coefficient.clone(),
        }
    }
    pub fn constant(&self) -> Coin {
        self.constant
    }
    pub fn coefficient(&self) -> Coin {
        self.coefficient
    }
    pub fn min_fee(&self, tx: &Transaction) -> Result<Coin, String> {
        // return (transaction byte length) * coefficient + constant
        let tx_byte_len = tx.to_bytes().len() as u64;
        let with_efficient = match tx_byte_len.checked_mul(self.coefficient()) {
            Some(value) => Ok(value),
            None => Err(String::from("overflow")),
        }?;
        match with_efficient.checked_add(self.constant()) {
            Some(value) => Ok(value),
            None => Err(String::from("overflow")),
        }
    }
}
