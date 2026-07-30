package stripepay

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// D9 says the portal holds zero home addresses. This is the mechanism that
// makes that true instead of merely written down.
//
// It exists because the property failed in exactly the way an unenforced
// property does. CanonicalSession carried the member's shipping name and street
// address as ordinary exported fields, the projector marshalled the whole struct
// into stripe_projection_applications.canonical, and three separate comments —
// D9, the struct's own doc, and the column's COMMENT — each asserted this could
// not happen. None of them was code. The address had never actually been written
// only because no webhook had yet been delivered.
//
// The test walks the struct rather than naming fields, so a ShippingPhone added
// next year is covered the day it appears: any field whose name marks it as
// address detail must not survive serialization, whatever it is called.
func TestCanonicalSessionNeverSerializesAnAddress(t *testing.T) {
	t.Parallel()

	// Every string field gets a marker naming itself, so a leak is traceable to
	// the field that leaked rather than to a value that might be a coincidence.
	var session CanonicalSession
	value := reflect.ValueOf(&session).Elem()
	fields := value.Type()
	markers := make(map[string]string, fields.NumField())
	for i := range fields.NumField() {
		field := fields.Field(i)
		if field.Type.Kind() != reflect.String {
			continue
		}
		marker := "LEAK-MARKER-" + field.Name
		value.Field(i).SetString(marker)
		markers[field.Name] = marker
	}

	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := string(raw)

	// Anything Stripe collects about where a member lives. Matched on the field
	// name so the rule survives renames and additions.
	forbidden := func(name string) bool {
		lower := strings.ToLower(name)
		for _, mark := range []string{"shipping", "address", "postal", "phone"} {
			if strings.Contains(lower, mark) {
				return true
			}
		}
		return false
	}

	checked := 0
	for name, marker := range markers {
		if !forbidden(name) {
			continue
		}
		checked++
		if strings.Contains(encoded, marker) {
			t.Errorf("%s survived serialization; D9 says this value is never stored.\n"+
				"Tag it json:\"-\" rather than relying on callers to strip it: %s", name, encoded)
		}
	}
	if checked == 0 {
		t.Fatal("no address-bearing fields were found, so this test asserted nothing; " +
			"if the fields were renamed, teach `forbidden` the new name")
	}

	// Positive control. Without it, a CanonicalSession that serialized to `{}` —
	// or a marshal that silently failed — would pass every assertion above while
	// destroying the audit record the column exists for.
	for _, required := range []string{"ID", "Currency", "CustomerID", "PaymentIntentID"} {
		if !strings.Contains(encoded, markers[required]) {
			t.Errorf("%s is missing from the canonical record: %s", required, encoded)
		}
	}
}
