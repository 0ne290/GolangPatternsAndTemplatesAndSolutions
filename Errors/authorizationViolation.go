package errors

// AuthorizationViolationError ...
type AuthorizationViolationError struct {
	Message string
}

// NewAuthorizationViolationError ...
func NewAuthorizationViolationError(message string) *AuthorizationViolationError {
	return &AuthorizationViolationError{message}
}

// Error ...
func (e *AuthorizationViolationError) Error() string {
	return e.Message
}
