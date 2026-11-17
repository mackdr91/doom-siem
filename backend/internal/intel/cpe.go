/*
Author: Domonick Mack
Date: 2026-11-17
Description: NIST NVD CPE API v2.0 client with CPE 2.3 parsing and short-lived response caching for Doom SIEM.
*/

package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultNVDCPBaseURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	defaultCacheTTL     = 5 * time.Minute
)

// CPEReference represents an external advisory or vendor reference URL on a CPE record.
type CPEReference struct {
	Ref  string `json:"ref"`
	Type string `json:"type,omitempty"`
}

// CPERecord represents a normalized Common Platform Enumeration (CPE 2.3) entry from NIST NVD.
type CPERecord struct {
	CPEName      string         `json:"cpe_name"`
	CPENameID    string         `json:"cpe_name_id"`
	Title        string         `json:"title"`
	Vendor       string         `json:"vendor"`
	Product      string         `json:"product"`
	Version      string         `json:"version"`
	Deprecated   bool           `json:"deprecated"`
	Created      string         `json:"created"`
	LastModified string         `json:"last_modified"`
	Refs         []CPEReference `json:"refs,omitempty"`
}

// CPESearchResponse wraps the normalized CPE search results returned by Doom SIEM.
type CPESearchResponse struct {
	Query          string      `json:"query"`
	TotalResults   int         `json:"total_results"`
	ResultsPerPage int         `json:"results_per_page"`
	Source         string      `json:"source"`
	Cached         bool        `json:"cached"`
	FetchedAtUTC   string      `json:"fetched_at_utc"`
	CPEs           []CPERecord `json:"cpes"`
}

// CPESearchOptions configures a CPE lookup request.
type CPESearchOptions struct {
	Keyword           string
	CPEMatchString    string
	Limit             int
	IncludeDeprecated bool
}

type cacheEntry struct {
	response  CPESearchResponse
	expiresAt time.Time
}

// CPEClient queries the NIST NVD CPE API v2.0 and caches recent lookups to respect rate limits.
type CPEClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]cacheEntry
}

// NewCPEClient constructs a new CPEClient with an optional NVD API key.
func NewCPEClient(apiKey string) *CPEClient {
	return &CPEClient{
		baseURL: defaultNVDCPBaseURL,
		apiKey:  strings.TrimSpace(apiKey),
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
		cache: make(map[string]cacheEntry),
	}
}

// SetBaseURL overrides the NVD CPE API v2.0 endpoint (used for testing).
func (c *CPEClient) SetBaseURL(endpoint string) {
	c.baseURL = strings.TrimRight(strings.TrimSpace(endpoint), "/")
}

// SearchCPEs queries the NIST NVD CPE API v2.0 for matching CPE 2.3 records.
func (c *CPEClient) SearchCPEs(ctx context.Context, opts CPESearchOptions) (*CPESearchResponse, error) {
	keyword := strings.TrimSpace(opts.Keyword)
	matchStr := strings.TrimSpace(opts.CPEMatchString)
	if keyword == "" && matchStr == "" {
		return nil, fmt.Errorf("either 'keyword' or 'cpe_match' query parameter is required")
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	cacheKey := fmt.Sprintf("%s|%s|%d|%t", strings.ToLower(keyword), strings.ToLower(matchStr), limit, opts.IncludeDeprecated)
	c.mu.RLock()
	if entry, ok := c.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		cachedResp := entry.response
		cachedResp.Cached = true
		c.mu.RUnlock()
		return &cachedResp, nil
	}
	c.mu.RUnlock()

	params := url.Values{}
	params.Set("resultsPerPage", strconv.Itoa(limit))
	if keyword != "" {
		params.Set("keywordSearch", keyword)
	}
	if matchStr != "" {
		params.Set("cpeMatchString", matchStr)
	}

	endpoint := fmt.Sprintf("%s?%s", c.baseURL, params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build NVD CPE request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Doom-SIEM/1.0")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD CPE API request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read NVD CPE response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD CPE API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var raw nvdCPEResponse
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		return nil, fmt.Errorf("failed to decode NVD CPE JSON: %w", err)
	}

	records := make([]CPERecord, 0, len(raw.Products))
	for _, item := range raw.Products {
		if !opts.IncludeDeprecated && item.CPE.Deprecated {
			continue
		}
		vendor, product, version := ParseCPE23Parts(item.CPE.CPEName)
		title := selectEnglishTitle(item.CPE.Titles)
		if title == "" {
			title = fmt.Sprintf("%s %s %s", vendor, product, version)
		}

		records = append(records, CPERecord{
			CPEName:      item.CPE.CPEName,
			CPENameID:    item.CPE.CPENameID,
			Title:        strings.TrimSpace(title),
			Vendor:       vendor,
			Product:      product,
			Version:      version,
			Deprecated:   item.CPE.Deprecated,
			Created:      item.CPE.Created,
			LastModified: item.CPE.LastModified,
			Refs:         item.CPE.Refs,
		})
	}

	displayQuery := keyword
	if displayQuery == "" {
		displayQuery = matchStr
	}

	result := CPESearchResponse{
		Query:          displayQuery,
		TotalResults:   raw.TotalResults,
		ResultsPerPage: len(records),
		Source:         "NIST NVD CPE API v2.0",
		Cached:         false,
		FetchedAtUTC:   time.Now().UTC().Format(time.RFC3339),
		CPEs:           records,
	}

	c.mu.Lock()
	c.cache[cacheKey] = cacheEntry{
		response:  result,
		expiresAt: time.Now().Add(defaultCacheTTL),
	}
	c.mu.Unlock()

	return &result, nil
}

// ParseCPE23Parts extracts vendor, product, and version from a standard CPE 2.3 URI.
func ParseCPE23Parts(cpeURI string) (vendor, product, version string) {
	// Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
	parts := strings.Split(cpeURI, ":")
	if len(parts) >= 6 && parts[0] == "cpe" && parts[1] == "2.3" {
		return cleanCPEComponent(parts[3]), cleanCPEComponent(parts[4]), cleanCPEComponent(parts[5])
	}
	return "unknown", "unknown", "*"
}

func cleanCPEComponent(val string) string {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" || trimmed == "*" || trimmed == "-" {
		return "*"
	}
	return strings.ReplaceAll(trimmed, "_", " ")
}

func selectEnglishTitle(titles []nvdCPETitle) string {
	for _, t := range titles {
		if strings.EqualFold(t.Lang, "en") && strings.TrimSpace(t.Title) != "" {
			return t.Title
		}
	}
	if len(titles) > 0 {
		return titles[0].Title
	}
	return ""
}

type nvdCPETitle struct {
	Title string `json:"title"`
	Lang  string `json:"lang"`
}

type nvdCPEResponse struct {
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
	Products       []struct {
		CPE struct {
			Deprecated   bool           `json:"deprecated"`
			CPEName      string         `json:"cpeName"`
			CPENameID    string         `json:"cpeNameId"`
			Created      string         `json:"created"`
			LastModified string         `json:"lastModified"`
			Titles       []nvdCPETitle  `json:"titles"`
			Refs         []CPEReference `json:"refs"`
		} `json:"cpe"`
	} `json:"products"`
}
