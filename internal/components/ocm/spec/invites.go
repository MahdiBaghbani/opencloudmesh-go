// Wire-format DTOs for POST /ocm/invite-accepted.
// See https://github.com/cs3org/OCM-API/blob/a5b5da6e17a598266b09a0445db8ac53b29daefc/IETF-OCM.md?plain=1#invite-acceptance-response-details
package spec

type InviteAcceptedRequest struct {
	RecipientProvider string `json:"recipientProvider"`
	Token             string `json:"token"`
	UserID            string `json:"userID"` //nolint:tagliatelle // OCM-API spec mandates 'userID' (capital ID), not camelCase 'userId'
	Email             string `json:"email"`
	Name              string `json:"name"`
}

type InviteAcceptedResponse struct {
	UserID string `json:"userID"` //nolint:tagliatelle // OCM-API spec mandates 'userID' (capital ID), not camelCase 'userId'
	Email  string `json:"email"`
	Name   string `json:"name"`
}
