package spec

import (
	"testing"
)

func TestWebDAVRequirementsAdmission_BoolSeam(t *testing.T) {
	t.Run("true+omit requires requirements", func(t *testing.T) {
		errs := ValidateWebDAVRequirementsAdmission(true, nil)
		if !hasValidationError(errs, "protocol.webdav.requirements") {
			t.Fatalf("expected REQUIRED for true+omit, got %v", errs)
		}
		for _, e := range errs {
			if e.Name == "protocol.webdav.requirements" && e.Message != "REQUIRED" {
				t.Fatalf("requirements error = %q, want REQUIRED", e.Message)
			}
		}
	})
	t.Run("false+omit allows empty", func(t *testing.T) {
		if errs := ValidateWebDAVRequirementsAdmission(false, nil); len(errs) != 0 {
			t.Fatalf("expected no admission error for false+omit, got %v", errs)
		}
	})
	t.Run("false+has reqs allows", func(t *testing.T) {
		reqs := []string{RequirementMustExchangeToken}
		if errs := ValidateWebDAVRequirementsAdmission(false, reqs); len(errs) != 0 {
			t.Fatalf("expected no admission error for false+has, got %v", errs)
		}
	})
	t.Run("true+has reqs allows", func(t *testing.T) {
		reqs := []string{RequirementMustExchangeToken}
		if errs := ValidateWebDAVRequirementsAdmission(true, reqs); len(errs) != 0 {
			t.Fatalf("expected no admission error for true+has, got %v", errs)
		}
	})
}

func TestWebappRequirementsAdmission_BoolSeam(t *testing.T) {
	t.Run("true+omit requires requirements", func(t *testing.T) {
		errs := ValidateWebappRequirementsAdmission(true, nil)
		if !hasValidationError(errs, "protocol.webapp.requirements") {
			t.Fatalf("expected REQUIRED for true+omit, got %v", errs)
		}
		for _, e := range errs {
			if e.Name == "protocol.webapp.requirements" && e.Message != "REQUIRED" {
				t.Fatalf("requirements error = %q, want REQUIRED", e.Message)
			}
		}
	})
	t.Run("false+omit allows empty at admission", func(t *testing.T) {
		// Admission alone does not enforce must-exchange-token; wire does.
		if errs := ValidateWebappRequirementsAdmission(false, nil); len(errs) != 0 {
			t.Fatalf("expected no admission error for false+omit, got %v", errs)
		}
	})
	t.Run("false+has reqs allows", func(t *testing.T) {
		reqs := []string{RequirementMustExchangeToken}
		if errs := ValidateWebappRequirementsAdmission(false, reqs); len(errs) != 0 {
			t.Fatalf("expected no admission error for false+has, got %v", errs)
		}
	})
	t.Run("true+has reqs allows", func(t *testing.T) {
		reqs := []string{RequirementMustExchangeToken}
		if errs := ValidateWebappRequirementsAdmission(true, reqs); len(errs) != 0 {
			t.Fatalf("expected no admission error for true+has, got %v", errs)
		}
	})
}
