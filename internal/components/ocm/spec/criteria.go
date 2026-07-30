package spec

// Canonical OCM discovery criteria wire values.
// Enum: spec.yaml:525-530
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/spec.yaml#L525-L530;
// denylist/allowlist semantics: IETF-OCM.md:759-762
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L759-L762.
const (
	CriteriaMustUseHTTPSig    = "must-use-http-sig"
	CriteriaMustExchangeToken = "must-exchange-token"
	CriteriaDenylist          = "denylist"
	CriteriaAllowlist         = "allowlist"
	CriteriaMustInvite        = "must-invite"
)

// KnownCriteria returns the five OCM spec criteria wire values.
func KnownCriteria() []string {
	return []string{
		CriteriaMustUseHTTPSig,
		CriteriaMustExchangeToken,
		CriteriaDenylist,
		CriteriaAllowlist,
		CriteriaMustInvite,
	}
}
