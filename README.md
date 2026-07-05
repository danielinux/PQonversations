<h1 align="center">PQonversations</h1>

<p align="center">Post-quantum end-to-end encrypted messaging for XMPP</p>

<p align="center">
  <em>A fork of <a href="https://codeberg.org/iNPUTmice/Conversations">Conversations</a> whose end-to-end encryption is the hybrid post-quantum <strong>x3dhpq</strong> protocol.</em>
</p>

## What is PQonversations?

PQonversations is a fork of [Conversations](https://codeberg.org/iNPUTmice/Conversations), the popular free and open-source Android XMPP/Jabber client. It keeps the whole Conversations experience — chats, group chats, calls, file sharing, push, battery-friendliness — but its **end-to-end encryption is [x3dhpq](#end-to-end-encryption), a hybrid post-quantum protocol**, instead of the classical scheme shipped by upstream.

Because the cryptography is different, **PQonversations is not interoperable with classical XMPP encryption**. It talks securely to other x3dhpq clients — for example the [Dino](https://dino.im) fork with x3dhpq support. It connects to any standard XMPP server and can still exchange *unencrypted* or OpenPGP messages with any client.

> **Status: experimental / pre-alpha.** x3dhpq is a young protocol; its specification is marked *Experimental* and has not yet had independent cryptographic review. Use PQonversations for evaluation and development, not yet as your only tool for high-risk communication. See [Security status](#security-status).

## Why post-quantum?

Store-and-forward messengers are uniquely exposed to *harvest-now, decrypt-later*: an adversary can archive ciphertext today and decrypt it once a quantum computer exists. Classical X25519/Diffie-Hellman key agreement is broken by such an adversary. x3dhpq is designed to resist this:

* **Post-quantum confidentiality.** Every session mixes classical X25519 with **ML-KEM-768** (FIPS 203) key encapsulation, so a recording made today cannot be decrypted by a future quantum computer. Messages are then protected by a Triple Ratchet (Double Ratchet + periodic ML-KEM checkpoints) for forward secrecy and post-compromise healing.
* **Post-quantum identity.** Long-term identities are signed with a hybrid **Ed25519 + ML-DSA-65** (FIPS 204) key; *both* signatures must verify, so breaking either primitive alone cannot forge an identity.
* **Verify a person once, not every device.** Trust is anchored in a per-account identity key. Verify a contact's fingerprint (or QR) once and all of their current and future devices are trusted automatically, with an append-only audit log so unauthorized device additions are detectable.
* **Standard XMPP, no special server.** x3dhpq is transport-only and runs on any standards-compliant XMPP server (Prosody, ejabberd, …) using ordinary PEP/PubSub — the same deployment model classical XMPP E2EE uses.
* **Keys protected at rest.** Private key material is wrapped with a hardware-backed AES-256-GCM key from the Android Keystore (no biometric setup required).

The protocol is specified in the accompanying `x3dhpq` draft.

## Features

Inherited from Conversations, with x3dhpq as the encryption layer:

* Post-quantum end-to-end encryption with **x3dhpq**, or [OpenPGP](https://openpgp.org/about/)
* Send and receive images and arbitrary files
* Encrypted audio/video calls ([DTLS-SRTP](https://help.conversations.im))
* Private group chats and public channels (with bookmarks)
* Share your location, send voice messages, emoji reactions, read markers
* High-resolution avatars and address-book integration
* Multiple accounts (unified inbox)
* Synchronizes across your own devices
* UnifiedPush support; very low impact on battery life

*Some features require server support (PEP/PubSub, HTTP File Upload, MAM, …).*

## End-to-end encryption

PQonversations offers two methods; pick one per conversation:

* **x3dhpq** — the default and recommended method. Post-quantum, works when a contact is offline, works across multiple devices, and after a one-time verification trusts all of a contact's devices. Use it whenever the other party also runs an x3dhpq-capable client.
* **OpenPGP** (XEP-0027) — a very old method with a few niche advantages, for people who know what they are doing.

Encryption is available in 1:1 chats and in private (members-only, non-anonymous) group chats. It is not offered in public channels, where anyone can join and participants cannot be verified.

## Server requirements

Any standards-compliant XMPP server works — no server-side x3dhpq code is required. Practically the server needs PEP/PubSub with `+notify`, and operators should allow reasonably large PEP items, since post-quantum key bundles are larger than classical ones. Prosody and ejabberd in their common configurations are fine.

## Install

PQonversations is **not** on Google Play or F-Droid — those host the original Conversations. Get it either way:

* **Download an APK** from this repository's [Releases](../../releases). A signed-for-sideloading APK is published automatically whenever a version tag is pushed (see [Releases & CI](#releases--ci)).
* **Build it yourself** — see [Building](#building).

> **Note:** this build shares the `eu.siacs.conversations` application id with upstream Conversations, so it **cannot be installed alongside** an existing Conversations install — you must uninstall Conversations first (which deletes its local message history). The published APK is debug-signed and intended for sideloading, not for app stores.

## Building

Requires the Android SDK and JDK 21.

```bash
./gradlew assembleConversationsFreeDebug
```

The APK is written to `./build/outputs/apk/conversationsFree/debug/`. The `conversationsFree` variant has no proprietary Google/FCM dependencies and builds without any signing secrets.

## Releases & CI

Pushing a tag triggers the `Release APK` GitHub Action (`.github/workflows/release-apk.yml`), which builds the `conversationsFree` APK and publishes it as a GitHub Release named for the tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

To ship a properly release-signed build instead of the debug-signed default, add a keystore and `signingConfig` and switch the workflow to `assembleConversationsFreeRelease`, storing the keystore and passwords as encrypted repository secrets.

## Security status

x3dhpq adapts, but does not inherit the security proofs of, Signal's PQXDH and Sparse Post-Quantum Ratchet, and it diverges from them in material ways. The specification is **Experimental** and **has not undergone independent cryptographic review**. Treat this app as pre-alpha: good for evaluation and development, not yet a drop-in replacement for a reviewed, production messenger. Post-quantum wrapping protects keys **at rest** (device theft, offline extraction), not against a compromised, running device.

## Relationship to Conversations & license

PQonversations is a downstream fork of [Conversations](https://codeberg.org/iNPUTmice/Conversations) by Daniel Gultsch and contributors. It is licensed under the **GPLv3**, inherited from Conversations, and is grateful for the upstream project's work. Everything except the x3dhpq encryption layer (and the removal of the classical scheme) is upstream Conversations.
