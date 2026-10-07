package churro

import (
	"errors"
	"fmt"
)

// ErrClosed is returned by Generator.Generate after Generator.Close.
var ErrClosed = errors.New("churro: generator is closed")

// ValidationError reports an invalid generation request.
type ValidationError struct {
	Field   string
	Problem string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("churro: invalid %s: %s", e.Field, e.Problem)
}
