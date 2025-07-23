package errors

// RelationViolationError ...
type RelationViolationError struct {
	Message string
}

// NewRelationViolationError ...
func NewRelationViolationError(message string) *RelationViolationError {
	return &RelationViolationError{message}
}

// Error ...
func (e *RelationViolationError) Error() string {
	return e.Message
}
