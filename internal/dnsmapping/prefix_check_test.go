package dnsmapping

import "testing"

func TestCheckPrefixDoesNotRebindOrAllocateWorkerPools(t *testing.T) {
	r := Registry{}
	id := Identity{Key: "A/1", GatewayID: "A", Generation: 1}
	if err := r.CheckPrefix(id, "198.19.0.0/20"); err != nil || len(r.pools) != 0 {
		t.Fatal("checking allocated a worker mapping", err)
	}
	finish, err := r.Begin(id, "198.19.0.0/20", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	if err := r.CheckPrefix(id, "198.19.0.0/20"); err != nil {
		t.Fatal(err)
	}
	if err := r.CheckPrefix(id, "198.19.16.0/20"); err == nil {
		t.Fatal("same worker generation rebound to another pool")
	}
	if err := r.CheckPrefix(id, "10.0.0.0/8"); err == nil {
		t.Fatal("invalid mapping pool accepted")
	}
}
