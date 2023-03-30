# Remix Auth WebAuthn

[![CI](https://github.com/ponjimon/remix-auth-webauthn/actions/workflows/test.yml/badge.svg)](https://github.com/ponjimon/remix-auth-webauthn/actions/workflows/test.yml)
[![Version](https://img.shields.io/npm/v/@ponjimon/remix-auth-webauthn.svg?&label=Version)](https://www.npmjs.com/package/@ponjimon/remix-auth-webauthn)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/ponjimon/remix-auth-webauthn/blob/main/LICENSE)

This strategy for Remix Auth provides WebAuthn support for authenticating users. It uses the [WebAuthn API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) to register and authenticate users based on the [SimpleWebAuthn](https://simplewebauthn.dev/) library.

# Understanding WebAuthn

> **Note**
> This section is still under construction.

```mermaid
sequenceDiagram
    User->>+Server: Action (Send Identifier e.g Email Address)
    Server->>+SessionStorage: Stores Registration Options
    SessionStorage->>-Server: Passes Registration Options to Loader
    Server->>-User: Loader (Gets Registration Options from Session)
    User->>+Device: Generates Passkey using prev. Registration Options
    Device->>-User: Returns Registration Response
    User->>+Server: Action (Send Username and RegistrationResponse)
    SessionStorage->>+Server: Get Challenge from Registration Options
    Server->>+User: Returns User object on verified registration
```

# Installation

> **Note**
> This section is still under construction.
