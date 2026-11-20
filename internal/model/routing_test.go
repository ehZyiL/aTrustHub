package model

import (
	"encoding/json"
	"github.com/qy/easyconnect/internal/routing"
	"testing"
)

func TestRoutingConfigRoundTripAndValidation(t *testing.T) {
	s := DefaultSettings()
	s.SharedExits = []routing.Group{{ID: "git", Pattern: "git.test", Protocol: "tcp", PortMin: 443, PortMax: 443, Gateways: []string{"A", "B"}}}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var restored Settings
	if err = json.Unmarshal(b, &restored); err != nil {
		t.Fatal(err)
	}
	restored.Normalize()
	if err = restored.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(restored.SharedExits) != 1 || restored.DialTimeoutMS != 5000 || restored.TotalTimeoutMS != 15000 {
		t.Fatal(restored)
	}
	for _, pattern := range []string{"*", "https://corp.test", "10.0.0.1/24", "bad..test"} {
		restored.SharedExits[0].Pattern = pattern
		if restored.Validate() == nil {
			t.Fatalf("accepted %q", pattern)
		}
	}
	s.DialTimeoutMS = 45001
	if s.Validate() == nil {
		t.Fatal("accepted overlong attempt")
	}
}
