package risk

import "time"

// Clock supplies time to the risk engine.
//
// Tests can inject a deterministic clock instead of using time.Sleep.
type Clock interface {
	Now() time.Time
}

// SystemClock uses the operating system's current UTC time.
type SystemClock struct{}

// Now returns the current time in UTC.
func (SystemClock) Now() time.Time {
	return time.Now().UTC()
}
