//go:build windows

package hyperv

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
// BUILTIN\Hyper-V Administrators => S-1-5-32-578
const hypervAdminGroupSid = "S-1-5-32-578"

func HasHyperVAdminRights() bool {
	sid, err := windows.StringToSid(hypervAdminGroupSid)
	if err != nil {
		return false
	}

	//  From MS docs:
	// "If TokenHandle is NULL, CheckTokenMembership uses the impersonation
	//  token of the calling thread. If the thread is not impersonating,
	//  the function duplicates the thread's primary token to create an
	//  impersonation token."
	token := windows.Token(0)
	member, err := token.IsMember(sid)

	if err != nil {
		logrus.Warnf("Token Membership Error: %s", err)
		return false
	}

	return member
}
