# Device Provider API 1

Status: **bounded experimental Alpha (Release Train E0)**.

Rextio separates Python-domain lowering from device/runtime integration:

```text
domain plugin                         device provider
Python API semantics                  hardware/runtime compatibility
claim/lower decisions                 target and driver preflight
typed DeviceRequirement        ->     declared TargetCapability
```

A device provider must not claim Python calls, operators, types, or syntax.
Those decisions remain in `rextio.plugins`. Conversely, a lowering plugin must
not silently select a CUDA driver, linker input, stream, allocator, or other
device integration.

## Version and selection

`rextio.devices.DEVICE_PROVIDER_API_VERSION` is `1.0` and evolves
independently from the lowering-plugin API. The reserved entry-point group is
`rextio.device_providers`, but E0 intentionally provides no implicit
entry-point loading.

Resolution takes an explicit `DeviceProviderSelection(provider_id,
capability_id)` plus an `ArtifactProfile` and a caller-supplied provider map.
Only the selected map member is inspected. Installed-but-unselected providers
cannot alter analysis, code generation, or result semantics.

No selection preserves the existing CPU-only behavior. A non-CPU
`DeviceRequirement` without an explicit selection fails closed.

## Structured records

`rextio.devices` exports immutable, deterministic records:

- `CanonicalDeviceId` and `normalize_device_id()` separate a backend-neutral
  logical kind/index (`gpu:0`) from the accelerator backend (`cuda`). Common
  PyTorch and TensorFlow spellings such as `cuda:0` and `/device:GPU:0` are
  normalized without inferring a backend for generic `GPU:N`.
- `DeviceValueMetadata` carries dtype, rank, layout, logical device, backend,
  runtime version, and optional static-shape facts as separate fields.
- `TargetCapability` carries target triples, artifact kinds, CPU feature
  level/features, accelerator backends, minimum runtime/driver versions,
  architecture identifiers, certification tier, and evidence references.
- `DeviceProviderManifest` carries provider/API identity, provider version,
  backend, capabilities, and runtime requirements.
- `DevicePreflightRequest` carries the exact artifact profile and explicit
  selection.
- `DevicePreflightResult` carries a closed status, stable reason codes, and
  bounded key/value observations. It always serializes
  `support_claim: false`; preflight is not certification.
- `DeviceBuildContribution` records bounded declarative Cargo features, native
  libraries, project-relative package references, generated-helper ids,
  runtime-check ids, and resource contracts.
- `ResolvedDevicePlan` combines the selected capability, successful preflight,
  and contribution, and projects deterministic `DeviceProviderLock` and
  `DeviceProviderReport` records.

Tuple inputs are canonicalized into stable lexical/id order and records are
frozen. A lock includes the SHA-256 of canonical manifest JSON, so provider
identity/version/capability and the target triple cannot drift silently.

## Fail-closed order

`resolve_device_plan()` performs the following order:

1. require an explicit selection for accelerator profiles;
2. select exactly one caller-supplied provider by id;
3. validate manifest/API/provider identity;
4. resolve exactly one named capability and check target, artifact kind,
   backend, and requested architecture compatibility;
5. run side-effect-free preflight;
6. require `ready`;
7. only then request declarative build contributions.

Provider exceptions, malformed records, unavailable/incompatible results, and
identity mismatches become `DeviceProviderError`. A failed native operation is
not replayable as Python; E0 fallback is allowed only before native side
effects, at this preflight boundary.

## Ownership boundary

`DeviceResourceContract` distinguishes provider-owned resources from
framework-owned resources. A provider-owned resource may use `owned` access.
A framework tensor, allocator, current stream, event, executor, context, or
handle may only use `borrow-validate`; a provider may not independently
allocate, replace, or synchronize it. Torch and TensorFlow will need
domain-plugin adapters before any such handoff is certified.

## Capability, preflight, and support are distinct

1. A manifest is declared metadata.
2. Preflight is a local observation for one artifact profile.
3. A build-only or experimental capability remains at that tier in reports.
4. Certification requires real execution evidence for the exact platform,
   architecture, runtime, driver, ownership, and lifetime contract.

A successful preflight cannot promote build-only evidence to certified device
support. Standard GitHub-hosted compilation and the Windows/Linux CUDA Driver
API inventory probe do not establish CUDA execution support.

## E0 limitations

E0 freezes the composition contract, not a CUDA product. Core does not yet
auto-discover providers or inject contributions into ordinary `rextio build`.
There is no first-party `rextio-device-cuda` package in this milestone, no GPU
kernel generation, no runtime dispatch, and no Torch/TensorFlow CUDA lowering.
Those require E1, E2, and E3 respectively, plus real NVIDIA hardware evidence.

ROCm, Metal/MPS, PJRT/TPU, and NPU adapters remain outside the first-party
commitment.
