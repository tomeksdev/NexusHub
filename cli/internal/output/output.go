// Package output formats CLI results. List commands default to an
// aligned text/tabwriter table; --json flips to a newline-delimited
// JSON body matching the backend envelope verbatim so jq pipelines
// work without intermediate munging.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Row is a single table row — header values and record values share
// the same shape so Table() can emit either.
type Row []string

// Table writes a tab-aligned table to w. Empty rows produce an empty
// table (just the header), matching the "no results" case most CLIs
// display.
func Table(w io.Writer, headers Row, rows []Row) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, strings.Join(headers, "\t")); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := fmt.Fprintln(tw, strings.Join(r, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// JSON writes v as pretty-printed JSON. Used under --json so callers
// can pipe into jq without reformatting the backend's response shape.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Truncate shortens s to at most n runes, appending an ellipsis when
// it had to cut. Handy for table cells carrying descriptions or long
// UUIDs — keeps the row on one line in a 120-col terminal.
func Truncate(s string, n int) string {
	if n <= 0 || len([]rune(s)) <= n {
		return s
	}
	runes := []rune(s)
	if n <= 1 {
		return string(runes[:n])
	}
	return string(runes[:n-1]) + "…"
}
