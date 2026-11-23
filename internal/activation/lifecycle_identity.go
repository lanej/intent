package activation

// BuildIdentity is injected by the owner build entrypoint and retained in the
// executing image. A pathname replacement cannot change this value.
var BuildIdentity string

func ImageIdentity() *string {
	if BuildIdentity == "" {
		return nil
	}

	identity := "build:" + BuildIdentity

	return &identity
}

func SameImage(first, second *string) bool {
	return first != nil && second != nil && *first == *second
}

// ProcessStartIdentity captures the kernel identity of a newly launched owner.
// Retained receipts compare this value as well as the PID before completion.
func ProcessStartIdentity(pid int) (string, error) { return processIdentity(pid) }
