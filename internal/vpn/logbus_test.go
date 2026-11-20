package vpn

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestLogBusFullRetainsOrderAndDeduplicatesRouteEvents(t *testing.T) {
	bus := NewLogBus(3)
	var file bytes.Buffer
	bus.SetSink(&file)
	checkTail := func(want ...string) {
		t.Helper()
		var got []string
		for _, e := range bus.Tail(0) {
			got = append(got, e.Source+":"+e.Line)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("tail = %v, want %v", got, want)
		}
	}
	bus.Add("app", "a\nb")
	bus.upsertRoute("access", "a", RouteEvent{Generation: 1})
	bus.upsertRoute("access", "c", RouteEvent{Generation: 2})
	checkTail("app:b", "access:a", "access:c")
	bus.upsertRoute("access", "a", RouteEvent{Generation: 3})
	checkTail("app:b", "access:c", "access:a")
	entry := bus.Tail(1)[0]
	if entry.Route == nil || entry.Route.Generation != 3 {
		t.Fatalf("latest duplicate did not refresh the route event: %+v", entry.Route)
	}
	if count := strings.Count(file.String(), "[access] a\n"); count != 1 {
		t.Fatalf("duplicate wrote %d log lines, want 1", count)
	}
	bus.Add("app", "d\ne")
	bus.upsertRoute("access", "f", RouteEvent{Generation: 4})
	checkTail("app:d", "app:e", "access:f")
	bus.upsertRoute("access", "a", RouteEvent{Generation: 5})
	checkTail("app:e", "access:f", "access:a")
	if count := strings.Count(file.String(), "[access] a\n"); count != 2 {
		t.Fatalf("entry was not logged again after eviction: got %d lines, want 2", count)
	}
}
