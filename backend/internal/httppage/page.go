// Package httppage holds the shared pagination, filtering, and sorting
// conventions used by every list endpoint in the v1 API.
//
// Query parameters:
//
//	limit   — max items to return. Default 50, clamped to [1, MaxLimit].
//	offset  — items to skip. Default 0, clamped to [0, ∞).
//	sort    — "<field>" or "-<field>" for descending. Optional; each
//	          endpoint declares its own allow-list of sortable fields.
//
// Response envelope (always the same shape):
//
//	{
//	  "items":  [...],
//	  "total":  123,
//	  "limit":  50,
//	  "offset": 0,
//	  "sort":   "-created_at"
//	}
//
// The envelope is JSON-stable so SDK generators and React-Query's
// pagination hooks don't need per-endpoint wrappers.
package httppage

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// MaxLimit is the hard ceiling applied regardless of what the client
// sends. Large list fetches should use streaming or chunked iteration —
// this endpoint family is for UIs, not exports.
const MaxLimit = 200

// DefaultLimit is the fallback when the client doesn't supply one. 50 is
// enough for a typical admin table without pushing scroll virtualisation.
const DefaultLimit = 50

// Params is the parsed pagination + sort input. SortField is empty when
// the client didn't request a sort, in which case handlers fall back to
// their own default ordering.
type Params struct {
	Limit     int
	Offset    int
	SortField string
	SortDesc  bool
}

// Parse pulls limit/offset/sort from the gin query string and clamps them
// to sane ranges. It never returns an error — invalid input is silently
// coerced to defaults, matching how most REST APIs behave under fuzzing
// or accidental double-encoding by a buggy frontend.
func Parse(c *gin.Context) Params {
	p := Params{Limit: DefaultLimit}

	if s := c.Query("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			switch {
			case n < 1:
				p.Limit = 1
			case n > MaxLimit:
				p.Limit = MaxLimit
			default:
				p.Limit = n
			}
		}
	}
	if s := c.Query("offset"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			p.Offset = n
		}
	}
	if s := c.Query("sort"); s != "" {
		p.SortField = strings.TrimPrefix(s, "-")
		p.SortDesc = strings.HasPrefix(s, "-")
	}
	return p
}

// ResolveSort returns the effective sort field, checking the caller-
// supplied allow-list. When the client's sort is empty or not in the
// list, fallback is used. This keeps SQL injection impossible at the
// handler layer: no user string is ever interpolated into a query.
func (p Params) ResolveSort(allowed []string, fallback string) (field string, desc bool) {
	if p.SortField == "" {
		return fallback, p.SortDesc
	}
	for _, a := range allowed {
		if a == p.SortField {
			return p.SortField, p.SortDesc
		}
	}
	return fallback, p.SortDesc
}

// Envelope is the response shape every list endpoint emits. Items is
// typed as `any` rather than a generic because gin.H is already
// untyped at the marshal boundary and introducing generics here gains
// nothing.
type Envelope struct {
	Items  any    `json:"items"`
	Total  int    `json:"total"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
	Sort   string `json:"sort,omitempty"`
}

// Wrap returns the response envelope. SortParam is the canonical form
// ("field" or "-field") that the handler actually applied — useful so
// clients can tell whether their requested sort was accepted.
func Wrap(items any, total int, p Params, sortField string, sortDesc bool) Envelope {
	sort := sortField
	if sortDesc && sort != "" {
		sort = "-" + sort
	}
	return Envelope{
		Items: items, Total: total,
		Limit: p.Limit, Offset: p.Offset,
		Sort: sort,
	}
}
