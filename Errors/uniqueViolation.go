package errors

// UniqueViolationError ...
type UniqueViolationError struct {
	Message string
}

// NewUniqueViolationError ...
func NewUniqueViolationError(message string) *UniqueViolationError {
	return &UniqueViolationError{message}
}

// Error ...
func (e *UniqueViolationError) Error() string {
	return e.Message
}
