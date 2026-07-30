package main

import "testing"

// The guard between a developer's .env and the live money catalog.
func TestCatalogSyncArgumentsGateLivePushes(t *testing.T) {
	t.Parallel()

	path, live, err := parseCatalogSyncArgs([]string{"catalog.json"})
	if err != nil || path != "catalog.json" || live {
		t.Errorf("plain args: path=%q live=%t err=%v", path, live, err)
	}

	path, live, err = parseCatalogSyncArgs([]string{"--yes-production", "catalog.json"})
	if err != nil || path != "catalog.json" || !live {
		t.Errorf("confirmed args: path=%q live=%t err=%v", path, live, err)
	}

	for name, args := range map[string][]string{
		"no path":      {},
		"flag only":    {"--yes-production"},
		"two paths":    {"a.json", "b.json"},
		"unknown flag": {"--force", "catalog.json"},
	} {
		if _, _, err := parseCatalogSyncArgs(args); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
