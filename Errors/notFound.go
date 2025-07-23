package errors

// NotFoundError ...
type NotFoundError struct {
	Message string
}

// NewNotFoundError ...
func NewNotFoundError(message string) *NotFoundError {
	return &NotFoundError{message}
}

// Error ...
func (e *NotFoundError) Error() string {
	return e.Message
}
