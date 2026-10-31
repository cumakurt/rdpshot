package playbook_test

import (
	"strings"
	"testing"

	"rdpshot/internal/playbook"
)

func TestPlaybooksAll(t *testing.T) {
	all := playbook.All()
	if len(all) == 0 {
		t.Fatal("expected playbooks, got empty list")
	}

	foundNLA := false
	for _, p := range all {
		if p.CheckID == "nla-not-required" {
			foundNLA = true
			if p.Scripts.PowerShell == "" {
				t.Errorf("nla-not-required missing PowerShell script")
			}
			if p.Scripts.Registry == "" {
				t.Errorf("nla-not-required missing Registry script")
			}
			if p.Scripts.Ansible == "" {
				t.Errorf("nla-not-required missing Ansible script")
			}
			if p.Scripts.Bash == "" {
				t.Errorf("nla-not-required missing Bash script")
			}
			if !strings.Contains(p.Scripts.PowerShell, "UserAuthentication") {
				t.Errorf("expected UserAuthentication in PowerShell script, got: %s", p.Scripts.PowerShell)
			}
		}
	}
	if !foundNLA {
		t.Fatal("nla-not-required playbook not found")
	}
}

func TestPlaybookGet(t *testing.T) {
	entry, ok := playbook.Get("bluekeep-cve-2019-0708")
	if !ok {
		t.Fatal("expected bluekeep playbook to exist")
	}
	if entry.Scripts.PowerShell == "" {
		t.Error("expected powershell script for bluekeep")
	}

	_, ok = playbook.Get("non-existent-check")
	if ok {
		t.Fatal("expected false for non-existent playbook")
	}
}
