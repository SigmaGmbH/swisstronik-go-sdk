### Swisstronik SDK Go

[![Test](https://github.com/SigmaGmbH/swisstronik-go-sdk/actions/workflows/test.yml/badge.svg)](https://github.com/SigmaGmbH/swisstronik-go-sdk/actions/workflows/test.yml)

This package provides a thin wrapper for Deoxys-II-256-128 (and maybe other things in the future) for usage v/ Swisstronik chain.

Currently, it exposes the following functions:

* EncryptState/DecryptState for smart contract enc/dec
* EncryptECDH/DecryptECDH for arbitrary data enc/dec with user's private key and node public key
* EncryptECDHWithRPCURL/DecryptECDHWithRPCURL - convenience encryption with pre-fetching node public key
* FetchNodePublicKey - for fetching node public key via JSON-RPC
* GetCurve25519PublicKey - for getting public key from private key
* DeriveEncryptionKey - for deriving a new master key using the other one and salt