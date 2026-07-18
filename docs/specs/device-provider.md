# Device Provider API draft

Status: **experimental design draft**, not Device Provider API 1.0.

Rextio separates Python-domain lowering from device/runtime integration:

```text
domain plugin                         future device provider
Python API semantics                  hardware/runtime compatibility
claim/lower decisions                 target and driver preflight
typed DeviceRequirement        ->     declared TargetCapability
```

A device provider must not claim Python calls, operators, types, or syntax.
Those decisions remain in `rextio.plugins`. Conversely, a lowering plugin must
not silently select a CUDA driver, linker input, stream, allocator, or other
device integration.

## Current draft records

`rextio.devices` exports immutable, deterministic records:

- `DeviceProviderManifest` carries provider identity, the exact draft API
  version, passive `TargetCapability` declarations, and runtime requirements.
- `DevicePreflightRequest` carries one resolved `ArtifactProfile`, including
  any domain-declared `DeviceRequirement` records.
- `DevicePreflightResult` carries a closed status, stable reason codes, and
  bounded key/value observations. Generic validation rejects control
  characters, overlong values, and obvious absolute paths; a provider remains
  responsible for semantic redaction until a typed observation vocabulary
  exists. It always serializes
  `support_claim: false`; preflight is not certification.
- The runtime-checkable `DeviceProvider` protocol exposes exactly
  `manifest()` and `preflight(request)`.

Tuple inputs are canonicalized into stable lexical/id order and the records are
frozen. The serialized form therefore does not depend on provider discovery or
filesystem order.

## Deliberately absent in Train C

There is no device-provider entry-point group, loader, resolver, config key,
build/link contribution, generated helper injection, runtime dispatch, or
provider selection. Core does not call this protocol during `check`,
`generate`, or `build`. A package merely implementing the structural protocol
does nothing to a Rextio build.

Those privileged surfaces require a later API RFC with explicit provider
selection, source locking, provenance, conflict resolution, and certification.
The first planned first-party implementation is NVIDIA CUDA. ROCm, Metal/MPS,
PJRT/TPU, and NPU adapters are deferred and may use the eventual public
third-party provider API; none is implied by this draft.

## Capability, preflight, and support are distinct

1. A manifest is declared metadata.
2. Preflight is a local observation for one artifact profile.
3. Certification requires real execution evidence for the exact platform,
   architecture, runtime, driver, ownership, and lifetime contract.

A successful preflight cannot promote build-only evidence to certified device
support. Standard GitHub-hosted compilation and the Windows inventory probe do
not establish CUDA execution support.

## Trust boundary

Future providers will be privileged because build/link/runtime integration can
execute tools and influence native artifacts. Unknown, unselected, unlocked,
or incompatible providers must fail closed before build side effects. Reports
must avoid environment dumps, credentials, identities, and machine-private
paths. The draft's generic report-safety checks are not a proof that arbitrary
provider strings contain no secrets. It intentionally offers no execution hook
beyond the provider-owned preflight method a caller explicitly invokes.
