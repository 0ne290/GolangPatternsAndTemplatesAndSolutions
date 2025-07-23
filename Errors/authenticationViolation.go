package errors

// AuthenticationViolationError ...
type AuthenticationViolationError struct {
	Message string
}

// NewAuthenticationViolationError ...
func NewAuthenticationViolationError(message string) *AuthenticationViolationError {
	return &AuthenticationViolationError{message}
}

// Error ...
func (e *AuthenticationViolationError) Error() string {
	return e.Message
}
