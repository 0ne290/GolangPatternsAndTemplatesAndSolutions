package errors

import (
	"fmt"
	"runtime"
)

// EnrichSource ...
func EnrichSource(target error) error {
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "unknown"
		line = 0
	}

	return fmt.Errorf("error: %w; source: %s : %d", target, file, line)
}
