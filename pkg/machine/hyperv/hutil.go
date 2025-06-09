//go:build windows

package hyperv

import (
	"fmt"

	"github.com/containers/podman/v5/pkg/machine/define"
	"github.com/sirupsen/logrus"
	win "golang.org/x/sys/windows"

	"github.com/containers/podman/v5/pkg/machine/windows"
)

func HasHyperVAdminRights() bool {
	sid, err := win.CreateWellKnownSid(win.WinBuiltinHyperVAdminsSid)
	if err != nil {
		return false
	}

	//  From MS docs:
	// "If TokenHandle is NULL, CheckTokenMembership uses the impersonation
	//  token of the calling thread. If the thread is not impersonating,
	//  the function duplicates the thread's primary token to create an
	//  impersonation token."
	token := win.Token(0)
	member, err := token.IsMember(sid)

	if err != nil {
		logrus.Warnf("Token Membership Error: %s", err)
		return false
	}

	return member
}

func LaunchHyperVElevated() error {
	fmt.Println("Launching HyperV as Admin to add user to hyperv Admin and registry...")
	if err := windows.LaunchElevate("Add user to HyperV Admin group", "Could not %s. See previous output for any potential failure details."); err != nil {
		return define.ErrInitRelaunchAttempt
	}
	return nil
}
