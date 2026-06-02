package config

// Persistence backend name constants. These are the only valid values for
// PersistenceConfig.Backend. Unknown values are rejected at validation time;
// there is no silent fallback to memory.
const (
	BackendMemory = "memory"
	BackendJSON   = "json"
	BackendSQLite = "sqlite"
	BackendMirror = "mirror"
)
