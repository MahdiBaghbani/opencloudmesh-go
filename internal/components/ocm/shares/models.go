// Package shares is a grouping package for share-related sub-packages.
// Domain models and repositories live in direction-aware sub-packages:
//   - shares/inbox: incoming share storage (IncomingShare, IncomingShareRepo)
//   - shares/outgoing: outgoing share storage (OutgoingShare, OutgoingShareRepo)
//   - shares/incoming: inbound OCM protocol handler (POST /ocm/shares)
package shares
