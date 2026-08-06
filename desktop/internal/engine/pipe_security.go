package engine

// The exact app user must be allowed because go-winio opens the accepting pipe
// instance from the unelevated UI process. SYSTEM and Administrators admit the
// elevated engine, including when UAC uses a different administrator account.
func pipeSecurityDescriptor(userSID string) string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + userSID + ")"
}
