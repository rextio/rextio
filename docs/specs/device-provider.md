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
`rextio.device_providers`.

Programmatic resolution takes an explicit
`DeviceProviderSelection(provider_id, capability_id)` plus an
`ArtifactProfile` and a caller-supplied provider map. The advanced
`[target].device_provider` / `device_capability` build configuration instead
loads exactly the named installed entry point. It does not enumerate, import,
or execute any unselected payload. The source lock binds the selected entry
point's group, name, `module:attribute` value, and installed distribution
name/version without recording filesystem locators.

No selection preserves the existing CPU-only behavior. A non-CPU
`DeviceRequirement` without an explicit selection fails closed. Conversely,
selecting an accelerator provider without a matching typed non-CPU
`DeviceRequirement` also fails closed. Merely installing/configuring
`rextio-device-cuda` therefore cannot turn a CPU-only domain route into CUDA.

`[target.device_options]` is a string map passed only to the explicitly
selected provider. It is not a secret store: provider code receives the raw
values. At most 64 entries are accepted; each public option key is a bounded
lowercase identifier of at most 64 characters, and each printable value is at
most 4096 characters. Rextio's public lock/report surfaces emit only sorted
option keys and a SHA-256 binding digest, and stable public errors do not echo
provider exception text or raw option values.

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
  runtime-check ids, and resource contracts. API 1 records the future surface;
  the current build materializer accepts only native-library names. Non-empty
  Cargo features, package references, helper ids, or runtime-check ids fail
  closed rather than being misrepresented as active integration.
- `ResolvedDevicePlan` combines the selected capability, successful preflight,
  and contribution, and projects deterministic `DeviceProviderLock` and
  `DeviceProviderReport` records.

Validated identifier, observation, and option inputs are canonicalized into
stable lexical/id order, resource contracts use their complete serialized
field tuple as the ordering key, and records are frozen. A lock includes
canonical manifest, artifact-profile, contribution, source-identity, and
redacted-options SHA-256 values, so the selected distribution/entry-point
target, provider identity/version/capability, target, and admitted inputs
cannot drift silently.

## Fail-closed order

`resolve_device_plan()` performs the following order:

1. require an explicit selection for accelerator profiles;
2. select exactly one caller-supplied provider by id, or load exactly one
   explicitly named installed entry point;
3. validate manifest/API/provider identity;
4. resolve exactly one named capability and check target, artifact kind,
   backend, and requested architecture compatibility;
5. run side-effect-free preflight;
6. require `ready`;
7. only then request declarative build contributions.

Provider exceptions, malformed records, unavailable/incompatible results, and
identity mismatches become `DeviceProviderError`. Public errors identify only
the stable stage/provider/status; the original exception remains chained for
local debugging and is not serialized. A failed native operation is not
replayable as Python; fallback is allowed only before native side effects, at
this preflight boundary.

For `rextio generate` and `rextio build`, selection and preflight complete
before generated directories or build outputs are reset. A successfully
resolved bounded host-extension contribution may emit:

- a validated native-link-only `build.rs`;
- `device-provider.lock.json`, containing the redacted resolved plan;
- conditional `device_provider_plans` in generate/build reports; and
- hashes of the generated link/lock inputs in artifact evidence, SBOM, and
  provenance when that evidence lane applies.

No-selection commands retain the prior report/file shape. The current
materializer has no concrete consumer for generic Cargo feature names, package
references, generated helpers, or runtime checks, so those inputs fail before
any generated-output write.

`rextio capabilities` remains passive configuration introspection. With no
selection it retains the legacy draft/unselected object. When
`device_provider` and `device_capability` are configured together, it reports
that public configured selection (`status: "configured"` and
`provider_selected: true`) without enumerating/importing the provider, running
preflight, or emitting provider option keys or values. Actual provider identity
validation and support facts remain generate/build-only.

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

## E0 / bounded integration limitations

This work freezes the composition contract and selected-provider build wiring,
not a CUDA framework product. Core deliberately does not auto-discover
providers. The separate first-party `rextio-device-cuda` E1 package can prove
driver/toolkit preflight and provider-owned raw-resource primitives, but E1
alone supplies no Python-domain semantics and cannot satisfy an ordinary
CPU-only artifact profile.

There is no GPU kernel generation, framework tensor/allocator/current-stream
handoff, or Torch/TensorFlow CUDA lowering in this milestone. Those require
separate E2 and E3 domain integrations plus exact real-NVIDIA-hardware
evidence. Until then, framework CUDA source remains Python fallback or fails a
native-only closure.

ROCm, Metal/MPS, PJRT/TPU, and NPU adapters remain outside the first-party
commitment.
