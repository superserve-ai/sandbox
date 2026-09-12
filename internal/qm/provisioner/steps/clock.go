package steps

import "time"

// timeNow is a seam for tests that need a fixed clock.
var timeNow = time.Now
