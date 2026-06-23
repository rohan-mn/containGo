package repository

import "errors"

// Shared repository errors allow callers to inspect failures with errors.Is.
var (
	ErrNotFound = errors.New(
		"repository record not found",
	)

	ErrConflict = errors.New(
		"repository record conflict",
	)

	ErrInvalidState = errors.New(
		"repository invalid state",
	)
)
