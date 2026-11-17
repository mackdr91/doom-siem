/*
Author: Domonick Mack
Date: 2026-11-17
Description: Unit tests for the NIST NVD CPE API v2.0 client, CPE 2.3 parser, and response cache.
*/

package intel_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/mackdr91/doom-siem/backend/internal/intel"
)

func TestSearchCPEsAndCaching(t *testing.T) {
	var hits atomic.Int32
	mockNVD := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("apiKey") != "test-nvd-key" {
			t.Errorf("expected apiKey header test-nvd-key, got %q", r.Header.Get("apiKey"))
		}
		if r.URL.Query().Get("keywordSearch") != "openssh" {
			t.Errorf("expected keywordSearch=openssh, got %q", r.URL.Query().Get("keywordSearch"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"resultsPerPage": 2,
			"startIndex": 0,
			"totalResults": 2,
			"products": [
				{
					"cpe": {
						"deprecated": false,
						"cpeName": "cpe:2.3:a:openbsd:openssh:9.8:*:*:*:*:*:*:*",
						"cpeNameId": "11111111-2222-3333-4444-555555555555",
						"created": "2024-07-01T12:00:00.000",
						"lastModified": "2024-07-02T12:00:00.000",
						"titles": [{"title": "OpenBSD OpenSSH 9.8", "lang": "en"}],
						"refs": [{"ref": "https://www.openssh.com/", "type": "Vendor"}]
					}
				},
				{
					"cpe": {
						"deprecated": true,
						"cpeName": "cpe:2.3:a:openbsd:openssh:4.0:*:*:*:*:*:*:*",
						"cpeNameId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
						"created": "2010-01-01T00:00:00.000",
						"lastModified": "2020-01-01T00:00:00.000",
						"titles": [{"title": "OpenBSD OpenSSH 4.0 (Deprecated)", "lang": "en"}]
					}
				}
			]
		}`))
	}))
	defer mockNVD.Close()

	client := intel.NewCPEClient("test-nvd-key")
	client.SetBaseURL(mockNVD.URL)

	// First request should hit NVD mock and filter out deprecated entry
	resp1, err := client.SearchCPEs(context.Background(), intel.CPESearchOptions{
		Keyword: "openssh",
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("SearchCPEs failed: %v", err)
	}
	if resp1.Cached {
		t.Errorf("expected first response Cached=false")
	}
	if len(resp1.CPEs) != 1 {
		t.Fatalf("expected 1 active CPE (deprecated filtered), got %d", len(resp1.CPEs))
	}
	if resp1.CPEs[0].Vendor != "openbsd" || resp1.CPEs[0].Product != "openssh" || resp1.CPEs[0].Version != "9.8" {
		t.Errorf("unexpected parsed CPE parts: %+v", resp1.CPEs[0])
	}

	// Second identical request should be served from cache
	resp2, err := client.SearchCPEs(context.Background(), intel.CPESearchOptions{
		Keyword: "openssh",
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("cached SearchCPEs failed: %v", err)
	}
	if !resp2.Cached {
		t.Errorf("expected second response Cached=true")
	}
	if hits.Load() != 1 {
		t.Errorf("expected 1 upstream HTTP call due to cache, got %d", hits.Load())
	}
}
