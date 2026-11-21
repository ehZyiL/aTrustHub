package capture

import (
	"net/netip"
	"testing"

	"github.com/ehzyil/connect-hub/internal/netpolicy"
)

func TestAliasAllocationPreservesExistingPoolsAndVPNResources(t *testing.T) {
	s := inventory(t, `[]`, `[{"dst":"0.0.0.0/0"},{"dst":"192.0.0.0/2"},{"dst":"198.18.0.0/16"}]`, `[{"set":{"elem":[{"prefix":{"addr":"198.19.0.0","len":17}}]}}]`)
	resources := []netpolicy.Range{{Min: "198.19.128.0", Max: "198.19.191.255"}}
	prefix, err := chooseAliasPrefix(s, resources, []string{"198.19.192.0/20", "198.19.208.0/20", "198.19.224.0/20"})
	if err != nil || prefix != "198.19.240.0/20" {
		t.Fatalf("allocation=%s %v", prefix, err)
	}
	if _, err := chooseAliasPrefix(s, resources, []string{"198.19.192.0/18"}); err == nil {
		t.Fatal("existing space reused")
	}
}
func TestAliasAllocationSeesNFTRangeNotJustEndpoints(t *testing.T) {
	s := inventory(t, `[]`, `[]`, `[{"map":{"elem":[{"range":["198.18.0.1","198.19.255.254"]}]}}]`)
	if _, err := chooseAliasPrefix(s, nil, nil); err == nil {
		t.Fatal("middle of existing NFT range reused")
	}
	s = inventory(t, `[]`, `[{"dst":"198.18.0.1"}]`, `[]`)
	prefix, err := chooseAliasPrefix(s, nil, nil)
	if err != nil || netip.MustParsePrefix(prefix).Contains(netip.MustParseAddr("198.18.0.1")) {
		t.Fatal("host route was not reserved")
	}
}

func TestAliasAllocationExcludesCorePoolWithoutAnyKernelRoute(t *testing.T) {
	s := inventory(t, `[]`, `[]`, `[]`)
	for range 32 {
		prefix, err := chooseAliasPrefix(s, nil, nil)
		if err != nil || netip.MustParsePrefix(prefix).Overlaps(netip.MustParsePrefix("198.18.0.0/16")) {
			t.Fatal("core resolver pool reused", prefix, err)
		}
	}
	if _, err := chooseAliasPrefix(s, nil, []string{"198.19.0.0/16"}); err == nil {
		t.Fatal("exhaustion fell back to upstream resolver's private pool")
	}
}

func TestAliasAllocationPreservesRequiredWorkerPoolOrRejects(t *testing.T) {
	s := inventory(t, `[]`, `[]`, `[]`)
	const wanted = "198.19.32.0/20"
	if got, err := chooseAliasPrefix(s, nil, nil, wanted); err != nil || got != wanted {
		t.Fatal(got, err)
	}
	if _, err := chooseAliasPrefix(s, nil, []string{wanted}, wanted); err == nil {
		t.Fatal("required worker pool ignored a retirement reservation")
	}
	s = inventory(t, `[]`, `[{"dst":"198.19.32.1"}]`, `[]`)
	if _, err := chooseAliasPrefix(s, nil, nil, wanted); err == nil {
		t.Fatal("required worker pool ignored a foreign host route")
	}
}
