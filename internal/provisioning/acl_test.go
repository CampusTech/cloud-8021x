package provisioning

import (
	"reflect"
	"testing"
)

func TestReviewedCAACLHardeningPreservesExistingAccess(t *testing.T) {
	original := DatabaseACL{Owner: "postgres", Grants: []Grant{
		{Grantor: "postgres", Role: "postgres", Privilege: "CREATE", Grantable: true},
		{Grantor: "postgres", Role: "postgres", Privilege: "CONNECT", Grantable: true},
		{Grantor: "postgres", Role: "PUBLIC", Privilege: "CONNECT"},
		{Grantor: "postgres", Role: "PUBLIC", Privilege: "TEMPORARY"},
		{Grantor: "postgres", Role: "other_ca_client", Privilege: "CONNECT"},
	}}
	expected, e := hardenedACL(original, []Access{{Role: "stepca", Connect: true, Temporary: true}}, "postgres")
	if e != nil {
		t.Fatal(e)
	}
	if len(expected.Grants) != 5 {
		t.Fatalf("grants=%+v", expected.Grants)
	}
	for _, g := range original.Grants {
		if g.Role != "PUBLIC" && !containsGrant(expected.Grants, g) {
			t.Fatalf("lost original grant %+v", g)
		}
	}
	if !containsGrant(expected.Grants, Grant{Grantor: "postgres", Role: "stepca", Privilege: "CONNECT"}) || !containsGrant(expected.Grants, Grant{Grantor: "postgres", Role: "stepca", Privilege: "TEMPORARY"}) {
		t.Fatal("CA access not made explicit")
	}
	if original.Grants[2].Role != "PUBLIC" {
		t.Fatal("mutated original inventory")
	}
	again, e := hardenedACL(expected, []Access{{Role: "stepca", Connect: true, Temporary: true}}, "postgres")
	if e != nil || !reflect.DeepEqual(again, expected) {
		t.Fatal("not idempotent")
	}
}
func TestHardeningRefusesUnreviewedPublicAuthority(t *testing.T) {
	for _, g := range []Grant{{Role: "PUBLIC", Privilege: "CREATE"}, {Role: "PUBLIC", Privilege: "CONNECT", Grantable: true}} {
		if _, e := hardenedACL(DatabaseACL{Owner: "postgres", Grants: []Grant{g}}, []Access{{Role: "stepca", Connect: true}}, "postgres"); e == nil {
			t.Fatal("accepted unexpected public privilege")
		}
	}
	if _, e := hardenedACL(DatabaseACL{Owner: "postgres"}, nil, "postgres"); e == nil {
		t.Fatal("missing approved CA client inventory accepted")
	}
}
func containsGrant(grants []Grant, want Grant) bool {
	for _, g := range grants {
		if g == want {
			return true
		}
	}
	return false
}
