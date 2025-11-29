package domain

// Delegation represents a placeholder for delegation logic between tenants or actors.
type Delegation struct {
	ParentScope string
	ChildScope  string
}

// Validate ensures a child scope cannot exceed the parent. Implementation pending.
func (d Delegation) Validate() bool {
	// TODO: implement real delegation validation rules
	return d.ChildScope == "" || d.ChildScope == d.ParentScope
}
