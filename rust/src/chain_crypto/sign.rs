use std::fmt;
use crate::chain_crypto::key;
use std::marker::PhantomData;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SignatureError {
    SizeInvalid { expected: usize, got: usize }, // expected, got in bytes
    StructureInvalid,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignatureError::SizeInvalid { expected, got } => write!(
                f,
                "Invalid Signature size expecting {} got {}",
                expected, got
            ),
            SignatureError::StructureInvalid => write!(f, "Invalid Signature structure"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    Failed,
    Success,
}

impl Into<bool> for Verification {
    fn into(self) -> bool {
        match self {
            Self::Success => true,
            Self::Failed => false,
        }
    }
}

impl From<bool> for Verification {
    fn from(b: bool) -> Self {
        match b {
            true => Verification::Success,
            false => Verification::Failed,
        }
    }
}

pub trait VerificationAlgorithm: key::AsymmetricPublicKey {
    type Signature: AsRef<[u8]> + Clone;
    const SIGNATURE_SIZE: usize;
    const SIGNATURE_BECH32_HRP: &'static str;
    fn verify_bytes(pubkey: &Self::Public, signature: &Self::Signature, msg: &[u8]) -> Verification;
    fn signature_from_bytes(data: &[u8]) -> Result<Self::Signature, SignatureError>;
}

pub trait SigningAlgorithm: key::AsymmetricKey where Self::PubAlg: VerificationAlgorithm {
    fn sign(key: &Self::Secret, msg: &[u8]) -> <Self::PubAlg as VerificationAlgorithm>::Signature;
}

pub struct Signature<T: ?Sized, A: VerificationAlgorithm> {
    signdata: A::Signature,
    phantom: PhantomData<T>,
}

impl<A: VerificationAlgorithm, T> Signature<T, A> {
    pub fn from_binary(sig: &[u8]) -> Result<Self, SignatureError> {
        Ok(Signature {
            signdata: A::signature_from_bytes(sig)?,
            phantom: PhantomData,
        })
    }
}

impl<T, A: VerificationAlgorithm> Clone for Signature<T, A> {
    fn clone(&self) -> Self {
        Signature {
            signdata: self.signdata.clone(),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<T: ?Sized, A: VerificationAlgorithm> AsRef<[u8]> for Signature<T, A> {
    fn as_ref(&self) -> &[u8] {
        self.signdata.as_ref()
    }
}

impl<A: VerificationAlgorithm, T> fmt::Display for Signature<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.signdata.as_ref()))
    }
}

impl<A: SigningAlgorithm> key::SecretKey<A> where <A as key::AsymmetricKey>::PubAlg: VerificationAlgorithm {
    pub fn sign<T: AsRef<[u8]>>(&self, object: &T) -> Signature<T, A::PubAlg> {
        Signature {
            signdata: <A as SigningAlgorithm>::sign(&self.0, object.as_ref()),
            phantom: PhantomData,
        }
    }
}
