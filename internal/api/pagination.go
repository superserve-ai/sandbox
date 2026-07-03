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

// likeEscaper escapes the LIKE/ILIKE pattern metacharacters so a
// user-supplied search term matches literally inside the '%…%' pattern the
// queries build around it. Backslash is Postgres's default LIKE escape
// character, so it must be escaped too (and first, which NewReplacer's
// single-pass semantics guarantee).
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// searchTerm normalizes a search query value for the sqlc name_search params:
// empty → nil (filter off), non-empty → pointer to the LIKE-escaped term.
func searchTerm(s string) *string {
	if s == "" {
		return nil
	}
	escaped := likeEscaper.Replace(s)
	return &escaped
}

// resolveTotal computes the X-Total-Count value for a list response: the
// number of rows matching the filters, ignoring limit and offset. It avoids
// the COUNT round trip whenever the returned page already proves the total —
// a page shorter than the limit (or with no limit at all) ends the list, so
// total = offset + pageLen. Only a full page, or an empty page at a nonzero
// offset (which proves nothing about how many rows precede it), needs the DB
// count.
func resolveTotal(pg pageParams, pageLen int, count func() (int64, error)) (int64, error) {
	var offset int64
	if pg.Offset != nil {
		offset = *pg.Offset
	}
	short := pg.Limit == nil || int64(pageLen) < *pg.Limit
	if short && (pageLen > 0 || offset == 0) {
		return offset + int64(pageLen), nil
	}
	return count()
}
