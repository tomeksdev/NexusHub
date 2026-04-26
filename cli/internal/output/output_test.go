package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestTruncate(t *testing.T) {
	cases := map[string]struct {
		in   string
		n    int
		want string
	}{
		"under": {"hello", 10, "hello"},
		"exact": {"hello", 5, "hello"},
		"over":  {"hello world", 6, "hello…"},
		"oneN":  {"hello", 1, "h"},
		"zeroN": {"hello", 0, "hello"},
		"runes": {"café", 3, "ca…"},
		"empty": {"", 5, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Truncate(c.in, c.n); got != c.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
			}
		})
	}
}

func TestTableEmitsHeaderAndRows(t *testing.T) {
	var buf bytes.Buffer
	err := Table(&buf, Row{"A", "B"}, []Row{{"1", "2"}, {"3", "4"}})
	if err != nil {
		t.Fatalf("Table: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"A", "B", "1", "2", "3", "4"} {
		if !strings.Contains(got, want) {
			t.Errorf("Table output missing %q:\n%s", want, got)
		}
	}
	// Header on the first line, first row second, second row third.
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d:\n%s", len(lines), got)
	}
	if !strings.Contains(lines[0], "A") || !strings.Contains(lines[0], "B") {
		t.Errorf("header line missing columns: %q", lines[0])
	}
}

func TestJSONProducesNewlineTerminated(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, map[string]int{"a": 1}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	s := buf.String()
	if !strings.HasSuffix(s, "\n") {
		t.Errorf("output should end with newline, got %q", s)
	}
	if !strings.Contains(s, "\"a\": 1") {
		t.Errorf("output missing the key: %q", s)
	}
}
