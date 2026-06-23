package apigateway

import "time"

// SystemClock supplies real UTC timestamps.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time {
	return time.Now().UTC()
}
