//! # Simplify SRP authentication.
//!
//! It uses [`srp`](https://crates.io/crates/srp) crate under the hood.
//!
//! Sign up flow:
//! 1. [`Client::sign_up`] - client creates salt and verifier for registration.
//!
//! And send it to server, to store it for future logins.
//!
//! Login flow:
//! 1. [`Client::login_hello`] - client creates login hello message with public key.
//! 2. [`Server::hello_reply`] - server responds with salt and its public key.
//! 3. [`Client::create_evidence`] - client creates evidence message to prove knowledge of password.
//! $. [`Server::authenticate`] - server verifies client evidence and responds with its own evidence.
//! 5. [`Client::verify_server`] - client verifies server evidence to complete authentication.
//!
//! And used structs can be serialized/deserialized for communication.
//!
//! That's all, it's simple!
//!
//! ## Example
//!
//! An example to help you to get started quickly. It's all together here for simplicity only.
//!
//! ```rust
//! use simple_srp::{Client, Server};
//!
//! let username = "testuser".to_string();
//! let password = "testpass".to_string();
//!
//! // Registration
//! let creds = Client::<srp::groups::G4096, sha2::Sha512>::sign_up(username.clone(), password.clone());
//!
//! // Login Hello
//! let (client_hello, client_keypair) = Client::<srp::groups::G4096, sha2::Sha512>::login_hello(username.clone());
//! let (server_hello, server_keypair) = Server::<srp::groups::G4096, sha2::Sha512>::hello_reply(
//!     creds.salt.clone(),
//!     creds.verifier.clone(),
//! ).unwrap();
//!
//! // Client creates evidence
//! let (login_evidence, client_session) = Client::<srp::groups::G4096, sha2::Sha512>::create_evidence(
//!     username.clone(),
//!     password.clone(),
//!     server_hello.salt.clone(),
//!     server_hello.server.clone(),
//!     client_keypair,
//! ).unwrap();
//!
//! // Server authenticates
//! let auth_result = Server::<srp::groups::G4096, sha2::Sha512>::authenticate(
//!     username.clone(),
//!     creds.salt.clone(),
//!     creds.verifier.clone(),
//!     server_keypair,
//!     client_hello.client.clone(),
//!     login_evidence.evidence.clone(),
//! ).unwrap();
//!
//! // Client verifies server evidence
//! let server_verification = Client::<srp::groups::G4096, sha2::Sha512>::verify_server(&client_session, auth_result.evidence.clone());
//! assert!(server_verification.is_ok());
//! ```

mod error;

pub use error::SimpleSrpError;

use std::marker::PhantomData;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use srp::{ClientVerifier, Group};

// To simplify work with hex strings

pub struct CryptoString(Vec<u8>);

impl CryptoString {
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn hex(self) -> String {
        hex::encode(self.0)
    }
}

impl From<Vec<u8>> for CryptoString {
    fn from(value: Vec<u8>) -> Self {
        CryptoString(value)
    }
}

impl TryFrom<String> for CryptoString {
    type Error = hex::FromHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        hex::decode(value).map(CryptoString::from)
    }
}

// For keys

pub struct KeyPair {
    pub private: CryptoString,
    pub public: CryptoString,
}

impl KeyPair {
    pub fn from_parts(private: String, public: String) -> Result<Self, hex::FromHexError> {
        Ok(KeyPair {
            private: CryptoString::try_from(private)?,
            public: CryptoString::try_from(public)?,
        })
    }
}

// Structs to communicate client-server SRP data

#[derive(Debug, Serialize, Deserialize)]
pub struct SignupCredentials {
    pub username: String,
    pub salt: String,
    pub verifier: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientHello {
    pub username: String,
    // Client public key (A)
    pub client: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerHello {
    pub salt: String,
    // Server public key (B)
    pub server: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginEvidence {
    // Client evidence (M1)
    pub evidence: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResult {
    pub result: bool,
    // Server evidence (M2)
    pub evidence: String,
}

pub struct Client<G: Group, D: Digest> {
    d: PhantomData<(G, D)>,
}

impl<G: Group, D: Digest> Client<G, D> {
    pub fn sign_up(username: String, password: String) -> SignupCredentials {
        let mut salt = [0u8; 64];
        rand::rng().fill_bytes(&mut salt);
        let verifier = srp::Client::<G, D>::new()
            .compute_verifier(
                username.as_bytes(),
                password.as_bytes(),
                &salt
            );

        SignupCredentials {
            username,
            salt: hex::encode(salt),
            verifier: hex::encode(verifier),
        }
    }

    // Client

    pub fn login_hello(username: String) -> (ClientHello, KeyPair) {
        let mut private = [0u8; 64];
        rand::rng().fill_bytes(&mut private);
        let public = srp::Client::<G, D>::new()
            .compute_public_ephemeral(&private);

        (
            ClientHello {
                username,
                client: hex::encode(&public),
            },
            KeyPair {
                private: Vec::from(private).into(),
                public: public.into(),
            },
        )
    }

    pub fn create_evidence(
        username: String, password: String,
        salt: String, server: String, pair: KeyPair
    ) -> Result<(LoginEvidence, ClientVerifier<D>), SimpleSrpError> {
        let client = srp::Client::<G, D>::new();
        let session = client.process_reply(
            pair.private.as_bytes(),
            username.as_bytes(),
            password.as_bytes(),
            &hex::decode(salt)?,
            &hex::decode(server)?,
        )?;

        Ok((
            LoginEvidence {
                evidence: hex::encode(session.proof()),
            },
            session,
        ))
    }

    pub fn verify_server(expected: &ClientVerifier<D>, server_evidence: String) -> Result<&[u8], SimpleSrpError> {
        expected.verify_server(&hex::decode(server_evidence)?)
            .map_err(SimpleSrpError::from)
    }
}

pub struct Server<G: Group, D: Digest> {
    d: PhantomData<(G, D)>,
}

impl<G: Group, D: Digest> Server<G, D> {
    pub fn hello_reply(salt: String, verifier: String) -> Result<(ServerHello, KeyPair), SimpleSrpError> {
        let mut private = [0u8; 64];
        rand::rng().fill_bytes(&mut private);
        let public = srp::Server::<G, D>::new()
            .compute_public_ephemeral(&private, &hex::decode(verifier)?);

        Ok((
            ServerHello {
                salt,
                server: hex::encode(&public),
            },
            KeyPair {
                private: Vec::from(private).into(),
                public: public.into(),
            },
        ))
    }

    pub fn authenticate(
        username: String, salt: String, verifier: String,
        pair: KeyPair, client: String, evidence: String
    ) -> Result<AuthResult, SimpleSrpError> {
        let server = srp::Server::<G, D>::new();
        let session = server.process_reply(
            username.as_bytes(),
            &hex::decode(salt)?,
            pair.private.as_bytes(),
            &hex::decode(verifier)?,
            &hex::decode(client)?,
        )?;
        session.verify_client(&hex::decode(evidence)?)?;

        Ok(AuthResult {
            result: true,
            evidence: hex::encode(session.proof()),
        })
    }
}
