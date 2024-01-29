### Swisstronik SDK Go


This package provides a thin wrapper for Deoxys-II-256-128 (and maybe other things in the future) for usage v/ Swisstronik chain.

Currently, it exposes the following functions:

* EncryptState/DecryptState for smart contract enc/dec
* EncryptECDH/DecryptECDH for arbitrary data enc/dec with user's private key and node public key
* GetCurve25519PublicKey - for getting public key from private key
* DeriveEncryptionKey - for deriving a new master key using the other one and salt