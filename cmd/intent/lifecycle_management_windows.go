//go:build windows

package main

import (
	"context"
	"errors"

	"github.com/lanej/intent/internal/activation"
)

func lifecycleStage(string, string) error {
	return errors.New("approval deployment requires Unix")
}

func lifecycleReplace(context.Context, string, string, string, activation.Request, string) (activation.Result, error) {
	return activation.Result{}, errors.New("approval replacement requires Unix")
}
