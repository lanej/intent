package intent

import (
	"context"

	"github.com/lanej/intent/internal/approvalforward"
)

// RemoteBrokerConfig chooses an owned 0700 directory and one explicitly paired Mac.
// Directory must be absolute and short enough for Directory/MacID-transportID.sock
// (two 32-character IDs) to fit within 103 bytes. MacID is a routing label, not a
// secret or cryptographic proof of machine identity.
type RemoteBrokerConfig struct {
	Directory string
	MacID     string
}

// ServeRemoteBroker owns Directory/approval.sock until ctx is cancelled. A user
// service or embedding application may call it; a second owner is rejected.
// Set INTENT_APPROVAL_SOCKET to that stable path for CLI and SDK callers.
//
// SSH creates private, unique transport sockets. New calls choose the newest
// live transport for MacID, ordered by socket modification time then basename.
// Selection precedes forwarding request bytes to the Mac. Submitted calls stay
// on their original transport; failure never replays a request on another one.
// SSH transport loss, caller EOF, or a deadline cancels a pending request. Remote
// shell exit alone may leave OpenSSH running while an approval channel is open.
// This function never establishes SSH transport or grants approval itself.
func ServeRemoteBroker(ctx context.Context, config RemoteBrokerConfig) error {
	return approvalforward.ServeRemote(ctx, config.Directory, config.MacID)
}
