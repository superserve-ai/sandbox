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

func TestOptStr(t *testing.T) {
	if optStr("") != nil {
		t.Error(`optStr("") should be nil`)
	}
	if got := optStr("x"); got == nil || *got != "x" {
		t.Errorf(`optStr("x") = %v, want pointer to "x"`, got)
	}
}
