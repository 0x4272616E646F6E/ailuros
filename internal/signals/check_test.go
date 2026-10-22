package signals

import (
	"testing"

	"github.com/0x4272616E646F6E/decision-waf/internal/policy"
)

func TestCheck(t *testing.T) {
	g := &GraphQL{Operations: 2, Batch: 3, Depth: 9, Fields: 40, Aliases: 7, Introspection: true}
	all := Signals{Smuggling: []string{"te_on_h2"}, WebSocket: &WebSocket{CrossOrigin: true, BadVersion: true}, JA4: "t12i_x", GraphQL: g}
	cases := []struct {
		s    Signals
		l    policy.Limits
		want string
	}{
		{all, policy.Limits{}, ""},
		{all, policy.Limits{Smuggling: policy.ActionBlock, GraphQL: policy.GraphQLLimits{MaxDepth: 1}}, "smuggling"},
		{all, policy.Limits{WebSocket: policy.WebSocketLimits{CrossOrigin: policy.ActionBlock}}, "websocket_cross_origin"},
		{all, policy.Limits{WebSocket: policy.WebSocketLimits{BadVersion: policy.ActionBlock}}, "websocket_bad_version"},
		{all, policy.Limits{JA4Block: []string{"t12i*"}}, "ja4"},
		{all, policy.Limits{GraphQL: policy.GraphQLLimits{MaxBatch: 2, MaxDepth: 1}}, "graphql_batch"},
		{all, policy.Limits{GraphQL: policy.GraphQLLimits{MaxOperations: 1}}, "graphql_operations"},
		{all, policy.Limits{GraphQL: policy.GraphQLLimits{Introspection: policy.ActionBlock}}, "graphql_introspection"},
		{all, policy.Limits{GraphQL: policy.GraphQLLimits{MaxDepth: 8}}, "graphql_depth"},
		{all, policy.Limits{GraphQL: policy.GraphQLLimits{MaxDepth: 9, MaxAliases: 6}}, "graphql_aliases"},
		{all, policy.Limits{GraphQL: policy.GraphQLLimits{MaxDepth: 8, MaxAliases: 6}}, "graphql_depth"},
		{all, policy.Limits{GraphQL: policy.GraphQLLimits{MaxFields: 39}}, "graphql_fields"},
		{all, policy.Limits{GraphQL: policy.GraphQLLimits{MaxDepth: 9, MaxFields: 40, MaxAliases: 7, MaxBatch: 3, MaxOperations: 2}}, ""},
		{Signals{}, policy.Limits{Smuggling: policy.ActionBlock, JA4Block: []string{"t*"}, GraphQL: policy.GraphQLLimits{MaxDepth: 1, Introspection: policy.ActionBlock}}, ""},
	}
	for i, c := range cases {
		got, hit := Check(c.s, c.l)
		if got != c.want || hit != (c.want != "") {
			t.Errorf("case %d: got %q %v, want %q", i, got, hit, c.want)
		}
	}
}
