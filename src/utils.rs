pub struct CryptoString(Vec<u8>);

impl CryptoString {
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[inline]
    pub fn hex(self) -> String {
        hex::encode(self.0)
    }
}

impl From<Vec<u8>> for CryptoString {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        CryptoString(value)
    }
}

impl TryFrom<String> for CryptoString {
    type Error = hex::FromHexError;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        hex::decode(value).map(CryptoString::from)
    }
}

pub struct KeyPair {
    pub private: CryptoString,
    pub public: CryptoString,
}

impl KeyPair {
    #[inline]
    pub fn from_parts(private: String, public: String) -> Result<Self, hex::FromHexError> {
        Ok(KeyPair {
            private: CryptoString::try_from(private)?,
            public: CryptoString::try_from(public)?,
        })
    }
}
