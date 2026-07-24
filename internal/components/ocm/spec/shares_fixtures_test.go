package spec

func hasValidationError(errs []ValidationError, name string) bool {
	for _, e := range errs {
		if e.Name == name {
			return true
		}
	}
	return false
}

func validWebapp() *WebappProtocol {
	return &WebappProtocol{
		URI:          "https://sender.example/apps/files/abc",
		Targets:      []string{"blank"},
		Permissions:  []string{"view", "read"},
		Requirements: []string{RequirementMustExchangeToken},
		SharedSecret: "topsecret",
	}
}
