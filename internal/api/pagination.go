package api

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// maxPageSize caps the rows a single paginated list request can return.
// Requests asking for more are silently clamped rather than rejected, so a
// client that hard-codes a larger page size still gets a valid response.
const maxPageSize = 200

// pageParams holds the normalized pagination + sort inputs shared by the list
// endpoints. Limit is nil when the caller supplied no `limit` query param,
// which the SQL treats as "return everything" — preserving the pre-pagination
// default for SDK/MCP callers that never send pagination.
type pageParams struct {
	Limit   *int64 // nil => no limit (return all rows)
	Offset  *int64 // nil => 0
	SortBy  string // validated against the caller's allow-list
	SortDir string // "asc" | "desc"
}

// parsePageParams reads limit/offset/sort/order from the query string,
// validates them against allowedSort, and applies defaults (sort=defaultSort,
// order=desc). It returns a user-facing error suitable for a 400 when any
// value is malformed; callers surface it via respondErrorMsg.
func parsePageParams(c *gin.Context, allowedSort []string, defaultSort string) (pageParams, error) {
	p := pageParams{SortBy: defaultSort, SortDir: "desc"}

	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return p, fmt.Errorf("limit must be a positive integer")
		}
		if n > maxPageSize {
			n = maxPageSize
		}
		lim := int64(n)
		p.Limit = &lim
	}

	if v := c.Query("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return p, fmt.Errorf("offset must be a non-negative integer")
		}
		off := int64(n)
		p.Offset = &off
	}

	if v := c.Query("sort"); v != "" {
		if !slices.Contains(allowedSort, v) {
			return p, fmt.Errorf("sort must be one of: %s", strings.Join(allowedSort, ", "))
		}
		p.SortBy = v
	}

	if v := c.Query("order"); v != "" {
		if v != "asc" && v != "desc" {
			return p, fmt.Errorf("order must be 'asc' or 'desc'")
		}
		p.SortDir = v
	}

	return p, nil
}

// optStr maps an empty query value to nil and a non-empty one to a pointer —
// the shape the generated sqlc params want for optional text filters.
func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
