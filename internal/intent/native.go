package intent

import (
	"context"
	"fmt"

	approval "github.com/lanej/intent"
	"github.com/lanej/intent/native"
)

func Native() Authenticate {
	return func(ctx context.Context, p Prompt) approval.Decision {
		result, err := native.Review(ctx, approval.Review{
			Title:   "Approve a remote request",
			Summary: fmt.Sprintf("SSH target: %s\nSession: %s\n\nThe remote caller supplies the reason below. Approval does not verify or execute the claimed action.", p.Host, p.Session),
			Details: p.Reason,
			Agent:   p.Agent,
		})
		if err != nil {
			return approval.Unavailable
		}

		return result.Decision
	}
}
