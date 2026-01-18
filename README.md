# Simplify SRP authentication.

It uses [`srp`](https://crates.io/crates/srp) crate under the hood.

Sign up flow:
1. [`Client::sign_up`] - client creates salt and verifier for registration.

And send it to server, to store it for future logins.

Login flow:
1. [`Client::login_hello`] - client creates login hello message with public key.
2. [`Server::hello_reply`] - server responds with salt and its public key.
3. [`Client::create_evidence`] - client creates evidence message to prove knowledge of password.
4. [`Server::authenticate`] - server verifies client evidence and responds with its own evidence.
5. [`Client::verify_server`] - client verifies server evidence to complete authentication.

And used structs can be serialized/deserialized for communication.

That's all, it's simple!

## Example

An example to help you to get started quickly. It's all together here for simplicity only.

```rust
use simple_srp::{Client, Server, groups};

let username = "testuser".to_string();
let password = "testpass".to_string();

let client = Client::<groups::G4096, sha2::Sha512>::new();
let server = Server::<groups::G4096, sha2::Sha512>::new();

// Registration
let creds = client.sign_up(username.clone(), password.clone());

// Login Hello
let (client_hello, client_keypair) = client.login_hello(username.clone());
let (server_hello, server_keypair) = server.hello_reply(
    creds.salt.clone(),
    creds.verifier.clone(),
).unwrap();

// Client creates evidence
let (login_evidence, client_session) = client.create_evidence(
    username.clone(),
    password.clone(),
    server_hello.salt.clone(),
    server_hello.server.clone(),
    client_keypair,
).unwrap();

// Server authenticates
let auth_result = server.authenticate(
    username.clone(),
    creds.salt.clone(),
    creds.verifier.clone(),
    server_keypair,
    client_hello.client.clone(),
    login_evidence.evidence.clone(),
).unwrap();

// Client verifies server evidence
let server_verification = client.verify_server(&client_session, auth_result.evidence.clone());
assert!(server_verification.is_ok());
```