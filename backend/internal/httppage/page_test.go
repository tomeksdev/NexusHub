package httppage

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func ginCtx(query string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/?"+query, nil)
	return c
}

func TestParseDefaults(t *testing.T) {
	p := Parse(ginCtx(""))
	if p.Limit != DefaultLimit || p.Offset != 0 || p.SortField != "" || p.SortDesc {
		t.Errorf("unexpected defaults: %+v", p)
	}
}

func TestParseClampLimit(t *testing.T) {
	cases := map[string]int{
		"limit=0":   1,
		"limit=-5":  1,
		"limit=500": MaxLimit,
		"limit=50":  50,
		"limit=abc": DefaultLimit,
	}
	for q, want := range cases {
		if got := Parse(ginCtx(q)).Limit; got != want {
			t.Errorf("%s: got %d, want %d", q, got, want)
		}
	}
}

func TestParseSortSign(t *testing.T) {
	p := Parse(ginCtx("sort=-created_at"))
	if p.SortField != "created_at" || !p.SortDesc {
		t.Errorf("desc sort parse: %+v", p)
	}
	p = Parse(ginCtx("sort=name"))
	if p.SortField != "name" || p.SortDesc {
		t.Errorf("asc sort parse: %+v", p)
	}
}

func TestResolveSortAllowList(t *testing.T) {
	p := Params{SortField: "password", SortDesc: true}
	field, desc := p.ResolveSort([]string{"name", "created_at"}, "name")
	if field != "name" || desc != true {
		t.Errorf("disallowed field not replaced: %s/%v", field, desc)
	}
	p = Params{SortField: "name"}
	field, _ = p.ResolveSort([]string{"name"}, "id")
	if field != "name" {
		t.Errorf("allowed field: got %s", field)
	}
	p = Params{}
	field, _ = p.ResolveSort([]string{"name"}, "id")
	if field != "id" {
		t.Errorf("empty field should fall to fallback: %s", field)
	}
}

func TestWrapEnvelope(t *testing.T) {
	env := Wrap([]int{1, 2}, 7, Params{Limit: 10, Offset: 20}, "name", true)
	if env.Sort != "-name" {
		t.Errorf("sort: %q", env.Sort)
	}
	if env.Total != 7 || env.Limit != 10 || env.Offset != 20 {
		t.Errorf("envelope fields: %+v", env)
	}
}
