//go:build !darwin

package native

import "context"

func materialize(context.Context) (string, error) { return "", nil }
