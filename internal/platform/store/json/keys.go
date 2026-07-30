package json

import "fmt"

// providerKey creates a lookup key for incoming shares.
func providerKey(senderHost, providerID string) string {
	return senderHost + ":" + providerID
}

// tokenUserKey creates a lookup key for incoming invites scoped to a recipient.
func tokenUserKey(token, recipientUserID string) string {
	return token + "\x00" + recipientUserID
}

// rebuildIndexes rebuilds all secondary indexes from primary data.
// Returns an error if any record has a duplicate index key, which indicates
// corrupted persisted data that must be resolved before use.
func (d *Driver) rebuildIndexes() error {
	d.webdavIndex = make(map[string]string)
	d.shareIDIndex = make(map[string]string)
	d.secretIndex = make(map[string]string)
	d.providerIndex = make(map[string]string)
	d.outgoingInviteTokenIndex = make(map[string]string)
	d.incomingInviteTokenUserIndex = make(map[string]string)

	if err := d.rebuildOutgoingShareIndexes(); err != nil {
		return err
	}

	if err := d.rebuildIncomingShareIndexes(); err != nil {
		return err
	}

	if err := d.rebuildOutgoingInviteIndexes(); err != nil {
		return err
	}

	if err := d.rebuildIncomingInviteIndexes(); err != nil {
		return err
	}

	return nil
}

func (d *Driver) rebuildOutgoingShareIndexes() error {
	for providerID, share := range d.outgoingShares {
		if share.WebDAVID != "" {
			if existingPid, exists := d.webdavIndex[share.WebDAVID]; exists {
				return fmt.Errorf(
					"corrupt data: duplicate outgoing share WebDAV id %q: provider ids %q and %q",
					share.WebDAVID, existingPid, providerID,
				)
			}

			d.webdavIndex[share.WebDAVID] = providerID
		}

		if share.ShareID != "" {
			if existingPid, exists := d.shareIDIndex[share.ShareID]; exists {
				return fmt.Errorf(
					"corrupt data: duplicate outgoing share share id %q: provider ids %q and %q", //nolint:dupword // intentional: preserved error text wording
					share.ShareID, existingPid, providerID,
				)
			}

			d.shareIDIndex[share.ShareID] = providerID
		}

		if share.SharedSecret != "" {
			if existingPid, exists := d.secretIndex[share.SharedSecret]; exists {
				return fmt.Errorf(
					"corrupt data: duplicate outgoing share shared secret %q: provider ids %q and %q",
					share.SharedSecret, existingPid, providerID,
				)
			}

			d.secretIndex[share.SharedSecret] = providerID
		}
	}

	return nil
}

func (d *Driver) rebuildIncomingShareIndexes() error {
	for shareID, share := range d.incomingShares {
		key := providerKey(share.SenderHost, share.ProviderID)
		if existingID, exists := d.providerIndex[key]; exists {
			return fmt.Errorf(
				"corrupt data: duplicate incoming share (senderHost=%q, providerId=%q): ids %q and %q",
				share.SenderHost, share.ProviderID, existingID, shareID,
			)
		}

		d.providerIndex[key] = shareID
	}

	return nil
}

func (d *Driver) rebuildOutgoingInviteIndexes() error {
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

	return nil
}

func (d *Driver) rebuildIncomingInviteIndexes() error {
	for id, invite := range d.incomingInvites {
		if invite.Token != "" && invite.RecipientUserID != "" {
			key := tokenUserKey(invite.Token, invite.RecipientUserID)
			if existingID, exists := d.incomingInviteTokenUserIndex[key]; exists {
				return fmt.Errorf(
					"corrupt data: duplicate incoming invite (token=%q, recipient=%q): ids %q and %q",
					invite.Token, invite.RecipientUserID, existingID, id,
				)
			}

			d.incomingInviteTokenUserIndex[key] = id
		}
	}

	return nil
}
