// Wire-format DTOs for POST /ocm/invite-accepted.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md?plain=1#invite-acceptance-response-details
package spec

// InviteAcceptedRequest carries the wire body for POST /ocm/invite-accepted.
type InviteAcceptedRequest struct {
	RecipientProvider string `json:"recipientProvider"`
	Token             string `json:"token"`
	UserID            string `json:"userID"` //nolint:tagliatelle // OCM-API spec mandates 'userID' (capital ID), not camelCase 'userId'
	Email             string `json:"email"`
	Name              string `json:"name"`
}

// InviteAcceptedResponse carries the wire body returned for an accepted invite.
type InviteAcceptedResponse struct {
	UserID string `json:"userID"` //nolint:tagliatelle // OCM-API spec mandates 'userID' (capital ID), not camelCase 'userId'
	Email  string `json:"email"`
	Name   string `json:"name"`
}
