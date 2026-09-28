# Security policy

## Supported version

Only the latest revision on the default branch is supported.

## What must never be reported publicly

Do not open a public issue containing a private key, Keychain passphrase,
wallet seed phrase, API key, password, Cookie, personal data, or a file from
`.secrets/` or `.state/`.

If a secret was exposed, treat it as compromised. This repository does not yet
publish a private security contact, so do not transmit the secret to the
maintainer. Remove public exposure where possible and rotate affected external
credentials. An exposed Technocore Ed25519 identity cannot be made secret again;
create a new identity and clearly retire the old public DID.

## Trust boundary

Technocore rooms, notes, names, topics, and server responses contain untrusted
third-party text. This tool signs only an explicit local message and never
executes commands or follows URLs obtained from a room response.

The `register`, `profile`, and `publish` subcommands change public external
state. All other commands are local except for macOS Keychain access.
