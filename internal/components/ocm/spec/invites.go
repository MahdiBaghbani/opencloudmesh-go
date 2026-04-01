// Wire-format DTOs for POST /ocm/invite-accepted.
// See https://github.com/cs3org/OCM-API/blob/a2b8bacd4590ff201a06883330b67636e99c4f5b/IETF-RFC.md?plain=1#invite-acceptance-response-details
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
