package intent_test

import (
	"context"
	"fmt"
	"time"

	approval "github.com/lanej/intent"
)

func ExampleClient_Approve() {
	client, err := approval.ClientFromEnv()
	if err != nil {
		if _, checkErr := fmt.Println(err); checkErr != nil {
			return
		}

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := client.Approve(ctx, approval.Request{Reason: "Deploy revision abc123 to production"})
	if err != nil {
		if _, checkErr := fmt.Println(err); checkErr != nil {
			return
		}

		return
	}

	if result.Decision != approval.Approved {
		if _, checkErr := fmt.Println("Deployment not approved:", result.Decision); checkErr != nil {
			return
		}

		return
	}
	// Execute the previously described action here.
	if _, checkErr := fmt.Println("Approval received:", result.RequestID); checkErr != nil {
		return
	}
}
