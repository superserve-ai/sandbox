package api

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func pageCtx(t *testing.T, rawQuery string) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/?"+rawQuery, nil)
	return c
}

var pageTestSortCols = []string{"created_at", "name", "status"}

func TestParsePageParams_DefaultsToUnpaginatedCreatedDesc(t *testing.T) {
	p, err := parsePageParams(pageCtx(t, ""), pageTestSortCols, "created_at")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Limit != nil {
		t.Errorf("Limit = %d, want nil (no limit → return all)", *p.Limit)
	}
	if p.Offset != nil {
		t.Errorf("Offset = %d, want nil", *p.Offset)
	}
	if p.SortBy != "created_at" || p.SortDir != "desc" {
		t.Errorf("sort = %q %q, want created_at desc", p.SortBy, p.SortDir)
	}
}

func TestParsePageParams_ValidValues(t *testing.T) {
	p, err := parsePageParams(pageCtx(t, "limit=25&offset=50&sort=name&order=asc"), pageTestSortCols, "created_at")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Limit == nil || *p.Limit != 25 {
		t.Errorf("Limit = %v, want 25", p.Limit)
	}
	if p.Offset == nil || *p.Offset != 50 {
		t.Errorf("Offset = %v, want 50", p.Offset)
	}
	if p.SortBy != "name" || p.SortDir != "asc" {
		t.Errorf("sort = %q %q, want name asc", p.SortBy, p.SortDir)
	}
}

func TestParsePageParams_LimitClampedToMax(t *testing.T) {
	p, err := parsePageParams(pageCtx(t, "limit=100000"), pageTestSortCols, "created_at")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Limit == nil || *p.Limit != maxPageSize {
		t.Errorf("Limit = %v, want clamp to %d", p.Limit, maxPageSize)
	}
}

func TestParsePageParams_Rejects(t *testing.T) {
	cases := map[string]string{
		"limit zero":         "limit=0",
		"limit negative":     "limit=-5",
		"limit non-numeric":  "limit=abc",
		"offset negative":    "offset=-1",
		"offset non-numeric": "offset=xyz",
		"unknown sort":       "sort=bogus",
		"bad order":          "order=sideways",
	}
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePageParams(pageCtx(t, query), pageTestSortCols, "created_at"); err == nil {
				t.Errorf("expected error for %q, got nil", query)
			}
		})
	}
}

func TestSearchTerm(t *testing.T) {
	if searchTerm("") != nil {
		t.Error(`searchTerm("") should be nil`)
	}
	cases := map[string]string{
		"plain":   "plain",
		"a_b":     `a\_b`,
		"50%":     `50\%`,
		`back\up`: `back\\up`,
		`%_\`:     `\%\_\\`,
	}
	for in, want := range cases {
		if got := searchTerm(in); got == nil || *got != want {
			t.Errorf("searchTerm(%q) = %v, want %q", in, got, want)
		}
	}
}

func ptr64(n int64) *int64 { return &n }

func TestResolveTotal(t *testing.T) {
	countErr := func() (int64, error) {
		t.Helper()
		t.Error("count should not be called")
		return 0, nil
	}
	count := func(n int64) func() (int64, error) {
		return func() (int64, error) { return n, nil }
	}

	cases := []struct {
		name  string
		pg    pageParams
		len   int
		count func() (int64, error)
		want  int64
	}{
		{"unpaginated", pageParams{}, 5, countErr, 5},
		{"unpaginated empty", pageParams{}, 0, countErr, 0},
		{"offset only", pageParams{Offset: ptr64(4)}, 1, countErr, 5},
		{"offset only past end", pageParams{Offset: ptr64(10)}, 0, count(5), 5},
		{"short page", pageParams{Limit: ptr64(10)}, 3, countErr, 3},
		{"short page with offset", pageParams{Limit: ptr64(10), Offset: ptr64(4)}, 1, countErr, 5},
		{"full page needs count", pageParams{Limit: ptr64(2)}, 2, count(9), 9},
		{"empty page at offset needs count", pageParams{Limit: ptr64(2), Offset: ptr64(50)}, 0, count(7), 7},
		{"empty page at zero offset", pageParams{Limit: ptr64(2)}, 0, countErr, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveTotal(tc.pg, tc.len, tc.count)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("total = %d, want %d", got, tc.want)
			}
		})
	}
}
