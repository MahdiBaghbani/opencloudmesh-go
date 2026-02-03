// Wire-format DTOs for POST /ocm/invite-accepted.
// See OCM-API spec v1.2.2 AcceptedInvite and related schemas.
package spec

// InviteAcceptedRequest is the server-to-server POST /ocm/invite-accepted body.
// All fields are spec-required (no omitempty).
type InviteAcceptedRequest struct {
	RecipientProvider string `json:"recipientProvider"`
	Token             string `json:"token"`
	UserID            string `json:"userID"`
	Email             string `json:"email"`
	Name              string `json:"name"`
}

// InviteAcceptedResponse is returned after successful invite acceptance.
// All fields are spec-required (no omitempty).
type InviteAcceptedResponse struct {
	UserID string `json:"userID"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}
