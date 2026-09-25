package users

import (
	"strings"

	"github.com/grioghar/flowsight/internal/core"
)

// publishMemberResolver wraps the existing member_resolver to add user: and usergroup: support.
func (m *Module) publishMemberResolver() {
	// Get the existing resolver if available
	var existing core.MemberResolver
	if svc := m.ctx.Service("member_resolver"); svc != nil {
		existing = svc.(core.MemberResolver)
	}

	resolver := &userMemberResolver{
		m:        m,
		delegate: existing,
	}

	m.ctx.Publish("member_resolver", resolver)
}

type userMemberResolver struct {
	m        *Module
	delegate core.MemberResolver
}

// Resolve returns CIDR addresses for user: and usergroup: references,
// or delegates to the wrapped resolver for other types.
func (ur *userMemberResolver) Resolve(ref string) []string {
	if strings.HasPrefix(ref, "user:") {
		return ur.resolveUser(ref[5:])
	}
	if strings.HasPrefix(ref, "usergroup:") {
		return ur.resolveUserGroup(ref[10:])
	}

	// Delegate to the wrapped resolver for other types
	if ur.delegate != nil {
		return ur.delegate.Resolve(ref)
	}

	return nil
}

// resolveUser returns all current addresses of a user's active sessions as CIDRs.
func (ur *userMemberResolver) resolveUser(user string) []string {
	ur.m.mu.RLock()
	defer ur.m.mu.RUnlock()

	addrs, exists := ur.m.userAddrs[user]
	if !exists {
		return nil
	}

	var cidrs []string
	for cidr := range addrs {
		cidrs = append(cidrs, cidr)
	}
	return cidrs
}

// resolveUserGroup returns all addresses of users who are members of the group.
// Group membership comes from LDAP cache.
func (ur *userMemberResolver) resolveUserGroup(group string) []string {
	ur.m.mu.RLock()
	defer ur.m.mu.RUnlock()

	var cidrs []string
	seen := make(map[string]bool)

	// Check each user's group membership
	for user, addrs := range ur.m.userAddrs {
		groups := ur.m.getUserGroups(user)
		for _, g := range groups {
			if g == group {
				// Add all addresses of this user
				for cidr := range addrs {
					if !seen[cidr] {
						cidrs = append(cidrs, cidr)
						seen[cidr] = true
					}
				}
				break
			}
		}
	}

	return cidrs
}

// ValidateUserMember extends core.ValidateMember to accept user: and usergroup: references.
// Call this from policy validation to replace the default ValidateMember when needed.
func ValidateUserMember(m string) (string, error) {
	m = strings.TrimSpace(m)

	// Check for user: and usergroup: prefixes
	if strings.HasPrefix(m, "user:") || strings.HasPrefix(m, "usergroup:") {
		prefix, name := m[:strings.Index(m, ":")], m[strings.Index(m, ":")+1:]
		if len(name) < 1 || len(m) > 100 {
			return "", &core.Error{Status: 400, Message: "invalid " + prefix + " reference"}
		}
		return m, nil
	}

	// Fall back to standard validation
	return core.ValidateMember(m)
}
