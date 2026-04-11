# cuda-did

Decentralized Identity for agents — DID/SPIFFE-like vessel identities with attestation (Rust)

Part of the Cocapn fleet — a Lucineer vessel component.

## What It Does

### Key Types

- `AgentDID` — core data structure
- `Attestation` — core data structure
- `DIDDocument` — core data structure
- `ServiceEndpoint` — core data structure
- `VerificationMethod` — core data structure
- `TrustRegistry` — core data structure
- _and 1 more (see source)_

## Quick Start

```bash
# Clone
git clone https://github.com/Lucineer/cuda-did.git
cd cuda-did

# Build
cargo build

# Run tests
cargo test
```

## Usage

```rust
use cuda_did::*;

// See src/lib.rs for full API
// 15 unit tests included
```

### Available Implementations

- `AgentDID` — see source for methods
- `Attestation` — see source for methods
- `DIDDocument` — see source for methods
- `TrustRegistry` — see source for methods
- `TrustBundle` — see source for methods

## Testing

```bash
cargo test
```

15 unit tests covering core functionality.

## Architecture

This crate is part of the **Cocapn Fleet** — a git-native multi-agent ecosystem.

- **Category**: other
- **Language**: Rust
- **Dependencies**: See `Cargo.toml`
- **Status**: Active development

## Related Crates


## Fleet Position

```
Casey (Captain)
├── JetsonClaw1 (Lucineer realm — hardware, low-level systems, fleet infrastructure)
├── Oracle1 (SuperInstance — lighthouse, architecture, consensus)
└── Babel (SuperInstance — multilingual scout)
```

## Contributing

This is a fleet vessel component. Fork it, improve it, push a bottle to `message-in-a-bottle/for-jetsonclaw1/`.

## License

MIT

---

*Built by JetsonClaw1 — part of the Cocapn fleet*
*See [cocapn-fleet-readme](https://github.com/Lucineer/cocapn-fleet-readme) for the full fleet roadmap*
