// Package peercompat provides peer profiles and the compiled compatibility
// contract that decides how this server interoperates with a specific peer or
// class of peers.
//
// # Four-layer pipeline
//
// Configuration flows through four layers before it becomes a runtime decision.
// Each layer has a single responsibility, which keeps the config-to-runtime
// path easy to audit.
//
//  1. Config layer. platform/config.PeerProfile describes compatibility
//     behavior in the on-disk/TOML shape, and config.PeerProfilesConfig groups
//     the custom profiles with config.PeerProfileMapping entries that bind a
//     domain pattern to a profile name.
//
//  2. Bridge into peercompat. profileFromConfig converts each
//     config.PeerProfile into the package-local Profile type, cloning slice
//     fields so a compiled profile never aliases config-owned memory. The
//     mapping shape is shared rather than copied: ProfileMapping is an alias
//     for config.PeerProfileMapping. profileFromConfig is the single bridge
//     between the config-layer profile shape and the peercompat profile shape,
//     so every compatibility field is mapped in exactly one place; new fields
//     must be added there.
//
//  3. Registry matching and defaults. ProfileRegistry (built via
//     NewProfileRegistry) holds the built-in profiles plus any custom profiles,
//     and resolves a peer domain to a Profile by matching the configured
//     mappings in order. When no mapping matches it falls back to the built-in
//     "strict" profile, so an unknown peer defaults to the most conservative
//     behavior.
//
//  4. Compiled typed decisions. BuildCompiledContractFromRegistry (and the
//     config-driven NewCompiledContractFromConfig) compiles each Profile into
//     an immutable CompiledProfile with typed signing, transport, token
//     exchange, and Basic auth decisions, and aggregates them into a
//     CompiledContract. Runtime code reads decisions from the contract via
//     ProfileForPeer and ProfileByName instead of re-interpreting raw config.
package peercompat
