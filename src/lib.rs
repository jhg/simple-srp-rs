#![doc = include_str!("../README.md")]

pub mod errors;
mod utils;

pub use srp::groups;

use std::marker::PhantomData;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use srp::{ClientVerifier, Group};

use errors::SimpleSrpError;
use utils::KeyPair;

// Structs to communicate client-server SRP data

#[derive(Debug, Serialize, Deserialize)]
pub struct SignupCredentials<U: AsRef<str> = String> {
    pub username: U,
    pub salt: String,
    pub verifier: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientHello<U: AsRef<str> = String> {
    pub username: U,
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

pub struct SrpClient<G: Group, D: Digest, const SALT_LEN: usize = 64, const PRIVATE_KEY_LEN: usize = 64> {
    d: PhantomData<(G, D)>,
}

impl<G: Group, D: Digest, const SALT_LEN: usize, const PRIVATE_KEY_LEN: usize> SrpClient<G, D, SALT_LEN, PRIVATE_KEY_LEN> {
    pub const fn new() -> Self {
        SrpClient {
            d: PhantomData,
        }
    }

    pub fn sign_up<U: AsRef<str>, P: AsRef<str>>(&self, username: U, password: P) -> SignupCredentials<U> {
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let verifier = srp::Client::<G, D>::new()
            .compute_verifier(
                username.as_ref().as_bytes(),
                password.as_ref().as_bytes(),
                &salt
            );

        SignupCredentials {
            username,
            salt: hex::encode(salt),
            verifier: hex::encode(verifier),
        }
    }


    pub fn login_hello<U: AsRef<str>>(&self, username: U) -> (ClientHello<U>, KeyPair) {
        let mut private = [0u8; PRIVATE_KEY_LEN];
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

    pub fn create_evidence<U: AsRef<str>, P: AsRef<str>>(
        &self,
        username: U, password: P,
        salt: String, server: String, pair: KeyPair
    ) -> Result<(LoginEvidence, ClientVerifier<D>), SimpleSrpError> {
        let client = srp::Client::<G, D>::new();
        let session = client.process_reply(
            pair.private.as_bytes(),
            username.as_ref().as_bytes(),
            password.as_ref().as_bytes(),
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

    pub fn verify_server<'a>(&self, expected: &'a ClientVerifier<D>, server_evidence: String) -> Result<&'a [u8], SimpleSrpError> {
        expected.verify_server(&hex::decode(server_evidence)?)
            .map_err(SimpleSrpError::from)
    }
}

pub struct SrpServer<G: Group, D: Digest, const PRIVATE_KEY_LEN: usize = 64> {
    d: PhantomData<(G, D)>,
}

impl<G: Group, D: Digest, const PRIVATE_KEY_LEN: usize> SrpServer<G, D, PRIVATE_KEY_LEN> {
    pub const fn new() -> Self {
        SrpServer {
            d: PhantomData,
        }
    }

    pub fn hello_reply(&self, salt: String, verifier: String) -> Result<(ServerHello, KeyPair), SimpleSrpError> {
        let mut private = [0u8; PRIVATE_KEY_LEN];
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
        &self,
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
