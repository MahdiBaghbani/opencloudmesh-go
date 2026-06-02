package json

import "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"

// Clone helpers return shallow copies at value boundaries.
// All four domain structs are flat (no pointer fields, slices, or maps),
// so a value copy is a full copy.

func cloneOutgoingShare(s *store.OutgoingShare) *store.OutgoingShare {
	c := *s
	return &c
}

func cloneIncomingShare(s *store.IncomingShare) *store.IncomingShare {
	c := *s
	return &c
}

func cloneOutgoingInvite(i *store.OutgoingInvite) *store.OutgoingInvite {
	c := *i
	return &c
}

func cloneIncomingInvite(i *store.IncomingInvite) *store.IncomingInvite {
	c := *i
	return &c
}
