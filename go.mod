module github.com/MahdiBaghbani/opencloudmesh-go

go 1.26.5

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/alicebob/miniredis/v2 v2.38.0
	github.com/glebarez/sqlite v1.11.0
	github.com/go-acme/lego/v4 v4.35.2
	github.com/go-chi/chi/v5 v5.3.1
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/google/uuid v1.6.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/valkey-io/valkey-go v1.0.76
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.57.0
	golang.org/x/sync v0.22.0
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/gorm v1.31.2
)

require github.com/klauspost/cpuid/v2 v2.0.12 // indirect

require (
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/glebarez/go-sqlite v1.21.2
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
	// Explicit pins so MVS selects these over the older versions glebarez/sqlite requires transitively.
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.56.0 // indirect
)
