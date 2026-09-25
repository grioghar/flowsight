package users

import (
	"fmt"
	"time"
)

// ldapEntry caches group membership with TTL.
type ldapEntry struct {
	groups    []string
	fetchedAt time.Time
}

// LDAP/AD user and group lookup support.
// This is a placeholder implementation. A full implementation would require
// either using an external LDAP library or implementing the full BER encoding.
// For now, this returns errors but allows the module to compile.

// lookupUserGroupsLDAP performs an LDAP bind and searches for the user's group membership.
func (m *Module) lookupUserGroupsLDAP(user string) ([]string, error) {
	if m.ldapConfig == nil {
		return nil, fmt.Errorf("LDAP not configured")
	}

	// Placeholder: In a full implementation, this would:
	// 1. Connect to the LDAP server
	// 2. Authenticate with the service account
	// 3. Search for the user
	// 4. Extract group membership from the user object or via group search
	// 5. Return the list of group names

	return nil, fmt.Errorf("LDAP user lookup not yet implemented - requires net/ldap or similar")
}
