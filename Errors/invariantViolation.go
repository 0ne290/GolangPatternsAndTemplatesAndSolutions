package errors

// InvariantViolationError ...
type InvariantViolationError struct {
	Message string
}

// NewInvariantViolationError ...
func NewInvariantViolationError(message string) *InvariantViolationError {
	return &InvariantViolationError{message}
}

// Error ...
func (e *InvariantViolationError) Error() string {
	return e.Message
}
