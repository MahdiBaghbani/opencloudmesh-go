package json

import "fmt"

// providerKey creates a lookup key for incoming shares.
func providerKey(sendingServer, providerId string) string {
	return sendingServer + ":" + providerId
}

// tokenUserKey creates a lookup key for incoming invites scoped to a recipient.
func tokenUserKey(token, recipientUserId string) string {
	return token + "\x00" + recipientUserId
}

// rebuildIndexes rebuilds all secondary indexes from primary data.
// Returns an error if any record has a duplicate index key, which indicates
// corrupted persisted data that must be resolved before use.
func (d *Driver) rebuildIndexes() error {
	d.webdavIndex = make(map[string]string)
	d.shareIdIndex = make(map[string]string)
	d.secretIndex = make(map[string]string)
	d.providerIndex = make(map[string]string)
	d.outgoingInviteTokenIndex = make(map[string]string)
	d.incomingInviteTokenUserIndex = make(map[string]string)

	for providerId, share := range d.outgoingShares {
		if share.WebDAVId != "" {
			if existingPid, exists := d.webdavIndex[share.WebDAVId]; exists {
				return fmt.Errorf(
					"corrupt data: duplicate outgoing share WebDAV id %q: provider ids %q and %q",
					share.WebDAVId, existingPid, providerId,
				)
			}
			d.webdavIndex[share.WebDAVId] = providerId
		}
		if share.ShareId != "" {
			if existingPid, exists := d.shareIdIndex[share.ShareId]; exists {
				return fmt.Errorf(
					"corrupt data: duplicate outgoing share share id %q: provider ids %q and %q",
					share.ShareId, existingPid, providerId,
				)
			}
			d.shareIdIndex[share.ShareId] = providerId
		}
		if share.SharedSecret != "" {
			if existingPid, exists := d.secretIndex[share.SharedSecret]; exists {
				return fmt.Errorf(
					"corrupt data: duplicate outgoing share shared secret %q: provider ids %q and %q",
					share.SharedSecret, existingPid, providerId,
				)
			}
			d.secretIndex[share.SharedSecret] = providerId
		}
	}

	for shareId, share := range d.incomingShares {
		key := providerKey(share.SendingServer, share.ProviderId)
		if existingID, exists := d.providerIndex[key]; exists {
			return fmt.Errorf(
				"corrupt data: duplicate incoming share (sendingServer=%q, providerId=%q): ids %q and %q",
				share.SendingServer, share.ProviderId, existingID, shareId,
			)
		}
		d.providerIndex[key] = shareId
	}

	for id, invite := range d.outgoingInvites {
		if invite.Token != "" {
			if existingID, exists := d.outgoingInviteTokenIndex[invite.Token]; exists {
				return fmt.Errorf(
					"corrupt data: duplicate outgoing invite token %q: ids %q and %q",
					invite.Token, existingID, id,
				)
			}
			d.outgoingInviteTokenIndex[invite.Token] = id
		}
	}

	for id, invite := range d.incomingInvites {
		if invite.Token != "" && invite.RecipientUserId != "" {
			key := tokenUserKey(invite.Token, invite.RecipientUserId)
			if existingID, exists := d.incomingInviteTokenUserIndex[key]; exists {
				return fmt.Errorf(
					"corrupt data: duplicate incoming invite (token=%q, recipient=%q): ids %q and %q",
					invite.Token, invite.RecipientUserId, existingID, id,
				)
			}
			d.incomingInviteTokenUserIndex[key] = id
		}
	}

	return nil
}
