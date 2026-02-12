// Wire-format DTOs for POST /ocm/invite-accepted.
// See https://github.com/cs3org/OCM-API/blob/615192eeff00bcd479364dfa9c1f91641ac7b505/IETF-RFC.md?plain=1#invite-acceptance-response-details
package spec

type InviteAcceptedRequest struct {
	RecipientProvider string `json:"recipientProvider"`
	Token             string `json:"token"`
	UserID            string `json:"userID"`
	Email             string `json:"email"`
	Name              string `json:"name"`
}

type InviteAcceptedResponse struct {
	UserID string `json:"userID"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}
