package store

import (
	"os"
	"testing"

	"github.com/dovocoder/reflag/internal/models"
)

func setupTestStore(t *testing.T) *Store {
	t.Helper()
	f, err := os.CreateTemp("", "reflag-test-*.db")
	if err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	s, err := New(f.Name())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestListOrgsForUser(t *testing.T) {
	s := setupTestStore(t)

	u1, err := s.GetOrCreateUser("a@example.com", "User A")
	if err != nil {
		t.Fatalf("create user 1: %v", err)
	}
	u2, err := s.GetOrCreateUser("b@example.com", "User B")
	if err != nil {
		t.Fatalf("create user 2: %v", err)
	}

	org1 := &models.Organization{ID: "org-1", Name: "Org One", Slug: "org-one"}
	org2 := &models.Organization{ID: "org-2", Name: "Org Two", Slug: "org-two"}
	org3 := &models.Organization{ID: "org-3", Name: "Org Three", Slug: "org-three"}
	for _, o := range []*models.Organization{org1, org2, org3} {
		if err := s.CreateOrg(o); err != nil {
			t.Fatalf("create org %s: %v", o.Slug, err)
		}
	}

	// u1 owns org1, is admin of org2
	mustAddMember(t, s, u1.ID, org1.ID, "owner")
	mustAddMember(t, s, u2.ID, org2.ID, "owner")
	// u1 is a viewer in org3
	mustAddMember(t, s, u1.ID, org3.ID, "viewer")

	u1Orgs, err := s.ListOrgsForUser(u1.ID)
	if err != nil {
		t.Fatalf("list orgs for user 1: %v", err)
	}
	if got := len(u1Orgs); got != 2 {
		t.Fatalf("expected user 1 to belong to 2 orgs, got %d", got)
	}
	seen := map[string]bool{}
	for _, o := range u1Orgs {
		seen[o.ID] = true
	}
	if !seen[org1.ID] || !seen[org3.ID] || seen[org2.ID] {
		t.Fatalf("unexpected org membership set: %v", seen)
	}

	u2Orgs, err := s.ListOrgsForUser(u2.ID)
	if err != nil {
		t.Fatalf("list orgs for user 2: %v", err)
	}
	if got := len(u2Orgs); got != 1 || u2Orgs[0].ID != org2.ID {
		t.Fatalf("expected user 2 to belong only to org 2, got %+v", u2Orgs)
	}
}

func mustAddMember(t *testing.T, s *Store, userID, orgID, role string) {
	t.Helper()
	m := &models.OrgMember{
		ID:     userID + "-" + orgID,
		UserID: userID,
		OrgID:  orgID,
		Role:   role,
	}
	if err := s.AddOrgMember(m); err != nil {
		t.Fatalf("add member: %v", err)
	}
}
