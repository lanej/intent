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
		fmt.Println(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := client.Approve(ctx, approval.Request{Reason: "Deploy revision abc123 to production"})
	if err != nil {
		fmt.Println(err)
		return
	}
	if result.Decision != approval.Approved {
		fmt.Println("Deployment not approved:", result.Decision)
		return
	}
	// Execute the previously described action here.
	fmt.Println("Approval received:", result.RequestID)
}
