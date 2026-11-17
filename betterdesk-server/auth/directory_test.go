package auth

import "testing"

func TestManagedCredentialDefaultRolePermissions(t *testing.T) {
	tests := []struct {
		role       string
		permission string
		want       bool
	}{
		{RoleGlobalAdmin, PermCredentialView, true},
		{RoleGlobalAdmin, PermCredentialRotate, true},
		{RoleGlobalAdmin, PermDirectorySync, true},
		{RoleOperator, PermCredentialView, true},
		{RoleOperator, PermDirectoryView, true},
		{RoleOperator, PermCredentialRotate, false},
		{RoleOperator, PermDirectorySync, false},
		{RoleViewer, PermCredentialView, false},
		{RoleViewer, PermDirectoryView, false},
	}
	for _, tt := range tests {
		if got := DefaultRolePermissions[tt.role][tt.permission]; got != tt.want {
			t.Errorf("role %s permission %s: got %v want %v", tt.role, tt.permission, got, tt.want)
		}
	}
}

func TestDirectoryGUIDAndParentDN(t *testing.T) {
	raw := []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	if got := formatADGUID(raw); got != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("formatADGUID: %s", got)
	}
	if got := directoryParentDN("CN=PC01,OU=Workstations,DC=example,DC=com"); got != "ou=Workstations,dc=example,dc=com" {
		t.Fatalf("directoryParentDN: %s", got)
	}
}
