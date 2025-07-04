package pomerium

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	pb "github.com/pomerium/pomerium/pkg/grpc/config"

	"github.com/pomerium/ingress-controller/model"
)

var testPPL = `{"allow":{"or":[{"domain":{"is":"pomerium.com"}}]}}`

func TestAnnotations(t *testing.T) {
	strp := func(txt string) *string { return &txt }
	r := &pb.Route{To: []string{"http://upstream.svc.cluster.local"}}
	ic := &model.IngressConfig{
		AnnotationPrefix: "a",
		Ingress: &networkingv1.Ingress{
			ObjectMeta: v1.ObjectMeta{
				Namespace: "test",
				Annotations: map[string]string{
					"a/allow_any_authenticated_user":            "false",
					"a/allow_public_unauthenticated_access":     "false",
					"a/allow_spdy":                              "true",
					"a/allow_websockets":                        "true",
					"a/allowed_domains":                         `["a"]`,
					"a/allowed_idp_claims":                      `key: ["val1", "val2"]`,
					"a/allowed_users":                           `["a"]`,
					"a/bearer_token_format":                     `idp_access_token`,
					"a/circuit_breaker_thresholds":              `{"max_connections": 1, "max_pending_requests": 2, "max_requests": 3, "max_retries": 4, "max_connection_pools": 5}`,
					"a/cors_allow_preflight":                    "true",
					"a/description":                             "DESCRIPTION",
					"a/depends_on":                              `["foo.example.com", "bar.example.com", "baz.example.com"]`,
					"a/health_checks":                           `[{"timeout": "10s", "interval": "1m", "healthy_threshold": 1, "unhealthy_threshold": 2, "http_health_check": {"path": "/"}}]`,
					"a/host_path_regex_rewrite_pattern":         "rewrite-pattern",
					"a/host_path_regex_rewrite_substitution":    "rewrite-sub",
					"a/host_rewrite_header":                     "rewrite-header",
					"a/host_rewrite":                            "rewrite",
					"a/idle_timeout":                            `60s`,
					"a/idp_access_token_allowed_audiences":      `["x","y","z"]`,
					"a/kubernetes_service_account_token_secret": "k8s_token",
					"a/lb_policy":                               "LEAST_REQUEST",
					"a/logo_url":                                "LOGO_URL",
					"a/least_request_lb_config":                 `{"choice_count":3,"active_request_bias":{"default_value":4,"runtime_key":"key"},"slow_start_config":{"slow_start_window":"3s","aggression":{"runtime_key":"key"}}}`,
					"a/pass_identity_headers":                   "true",
					"a/policy":                                  testPPL,
					"a/prefix_rewrite":                          "/",
					"a/preserve_host_header":                    "true",
					"a/regex_rewrite_pattern":                   `^/service/([^/]+)(/.*)$`,
					"a/regex_rewrite_substitution":              `\\2/instance/\\1`,
					"a/remove_request_headers":                  `["a"]`,
					"a/rewrite_response_headers":                `[{"header": "a", "prefix": "b", "value": "c"}]`,
					"a/secure_upstream":                         "true",
					"a/set_request_headers_secret":              `request_headers`,
					"a/set_request_headers":                     `{"a": "aaa"}`,
					"a/set_response_headers_secret":             `response_headers`,
					"a/set_response_headers":                    `{"disable": true}`,
					"a/timeout":                                 `2m`,
					"a/tls_client_secret":                       "my_client_secret",
					"a/tls_custom_ca_secret":                    "my_custom_ca_secret",
					"a/tls_downstream_client_ca_secret":         "my_downstream_client_ca_secret",
					"a/tls_server_name":                         "my.server.name",
					"a/tls_skip_verify":                         "true",
				},
			},
		},
		Secrets: map[types.NamespacedName]*corev1.Secret{
			{Name: "my_custom_ca_secret", Namespace: "test"}: {
				Data: map[string][]byte{
					model.CAKey: []byte("my_custom_ca_secret+cert"),
				},
			},
			{Name: "my_client_secret", Namespace: "test"}: {
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       []byte("my_client_secret+cert"),
					corev1.TLSPrivateKeyKey: []byte("my_client_secret+key"),
				},
			},
			{Name: "my_downstream_client_ca_secret", Namespace: "test"}: {
				Data: map[string][]byte{
					model.CAKey: []byte("my_downstream_client_ca_secret+cert"),
				},
			},
			{Name: "k8s_token", Namespace: "test"}: {
				Data: map[string][]byte{
					model.KubernetesServiceAccountTokenSecretKey: []byte("k8s-token-data"),
				},
				Type: corev1.SecretTypeServiceAccountToken,
			},
			{Name: "request_headers", Namespace: "test"}: {
				Data: map[string][]byte{
					"req_key_1": []byte("req_data1"),
					"req_key_2": []byte("req_data2"),
				},
				Type: corev1.SecretTypeOpaque,
			},
			{Name: "response_headers", Namespace: "test"}: {
				Data: map[string][]byte{
					"res_key_1": []byte("res_data1"),
					"res_key_2": []byte("res_data2"),
				},
				Type: corev1.SecretTypeOpaque,
			},
		},
	}
	require.NoError(t, applyAnnotations(r, ic))
	require.Empty(t, cmp.Diff(r, &pb.Route{
		TlsCustomCa:                      base64.StdEncoding.EncodeToString([]byte("my_custom_ca_secret+cert")),
		TlsDownstreamClientCa:            base64.StdEncoding.EncodeToString([]byte("my_downstream_client_ca_secret+cert")),
		TlsClientCert:                    base64.StdEncoding.EncodeToString([]byte("my_client_secret+cert")),
		TlsClientKey:                     base64.StdEncoding.EncodeToString([]byte("my_client_secret+key")),
		CorsAllowPreflight:               true,
		AllowPublicUnauthenticatedAccess: false,
		AllowAnyAuthenticatedUser:        false,
		Timeout:                          durationpb.New(time.Minute * 2),
		IdleTimeout:                      durationpb.New(time.Minute),
		AllowWebsockets:                  true,
		AllowSpdy:                        true,
		KubernetesServiceAccountToken:    "k8s-token-data",
		SetRequestHeaders:                map[string]string{"a": "aaa", "req_key_1": "req_data1", "req_key_2": "req_data2"},
		RemoveRequestHeaders:             []string{"a"},
		SetResponseHeaders:               map[string]string{"disable": "true", "res_key_1": "res_data1", "res_key_2": "res_data2"},
		RewriteResponseHeaders: []*pb.RouteRewriteHeader{{
			Header:  "a",
			Matcher: &pb.RouteRewriteHeader_Prefix{Prefix: "b"},
			Value:   "c",
		}},
		PreserveHostHeader:               true,
		HostRewrite:                      strp("rewrite"),
		HostRewriteHeader:                strp("rewrite-header"),
		HostPathRegexRewritePattern:      strp("rewrite-pattern"),
		HostPathRegexRewriteSubstitution: strp("rewrite-sub"),
		PassIdentityHeaders:              proto.Bool(true),
		PrefixRewrite:                    "/",
		RegexRewritePattern:              `^/service/([^/]+)(/.*)$`,
		RegexRewriteSubstitution:         `\\2/instance/\\1`,
		EnvoyOpts: &envoy_config_cluster_v3.Cluster{
			HealthChecks: []*envoy_config_core_v3.HealthCheck{{
				Timeout:            durationpb.New(time.Second * 10),
				Interval:           durationpb.New(time.Minute),
				UnhealthyThreshold: wrapperspb.UInt32(2),
				HealthyThreshold:   wrapperspb.UInt32(1),
				HealthChecker: &envoy_config_core_v3.HealthCheck_HttpHealthCheck_{
					HttpHealthCheck: &envoy_config_core_v3.HealthCheck_HttpHealthCheck{Path: "/"},
				},
			}},
			LbPolicy: envoy_config_cluster_v3.Cluster_LEAST_REQUEST,
			LbConfig: &envoy_config_cluster_v3.Cluster_LeastRequestLbConfig_{
				LeastRequestLbConfig: &envoy_config_cluster_v3.Cluster_LeastRequestLbConfig{
					ChoiceCount: &wrapperspb.UInt32Value{
						Value: 3,
					},
					ActiveRequestBias: &envoy_config_core_v3.RuntimeDouble{
						DefaultValue: 4,
						RuntimeKey:   "key",
					},
					SlowStartConfig: &envoy_config_cluster_v3.Cluster_SlowStartConfig{
						SlowStartWindow: &durationpb.Duration{
							Seconds: 3,
							Nanos:   0,
						},
						Aggression: &envoy_config_core_v3.RuntimeDouble{
							DefaultValue: 0,
							RuntimeKey:   "key",
						},
					},
				},
			},
		},
		Policies: []*pb.Policy{{
			AllowedUsers:   []string{"a"},
			AllowedDomains: []string{"a"},
			AllowedIdpClaims: map[string]*structpb.ListValue{
				"key": {Values: []*structpb.Value{structpb.NewStringValue("val1"), structpb.NewStringValue("val2")}},
			},
			SourcePpl: proto.String(`{"allow":{"or":[{"domain":{"is":"pomerium.com"}}]}}`),
		}},
		TlsSkipVerify:                  true,
		TlsServerName:                  "my.server.name",
		Description:                    "DESCRIPTION",
		LogoUrl:                        "LOGO_URL",
		BearerTokenFormat:              pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN.Enum(),
		IdpAccessTokenAllowedAudiences: &pb.Route_StringList{Values: []string{"x", "y", "z"}},
		DependsOn:                      []string{"foo.example.com", "bar.example.com", "baz.example.com"},
		CircuitBreakerThresholds: &pb.CircuitBreakerThresholds{
			MaxConnections:     proto.Uint32(1),
			MaxPendingRequests: proto.Uint32(2),
			MaxRequests:        proto.Uint32(3),
			MaxRetries:         proto.Uint32(4),
			MaxConnectionPools: proto.Uint32(5),
		},
	}, cmpopts.IgnoreUnexported(
		pb.Route{},
		pb.Route_StringList{},
		pb.RouteRewriteHeader{},
		pb.Policy{},
		structpb.ListValue{},
		structpb.Value{},
		durationpb.Duration{},
		envoy_config_cluster_v3.Cluster{},
		envoy_config_core_v3.HealthCheck{},
		envoy_config_core_v3.HealthCheck_HttpHealthCheck_{},
		envoy_config_core_v3.HealthCheck_HttpHealthCheck{},
		envoy_config_cluster_v3.Cluster_LeastRequestLbConfig{},
		envoy_config_core_v3.RuntimeDouble{},
		envoy_config_cluster_v3.Cluster_SlowStartConfig{},
		wrapperspb.UInt32Value{},
		pb.CircuitBreakerThresholds{},
	),
		cmpopts.IgnoreFields(pb.Policy{}, "Rego")))
	require.NotEmpty(t, r.Policies[0].Rego)
}

func TestMissingTlsAnnotationsSecretData(t *testing.T) {
	r := &pb.Route{To: []string{"http://upstream.svc.cluster.local"}}
	ic := &model.IngressConfig{
		AnnotationPrefix: "a",
		Ingress: &networkingv1.Ingress{
			ObjectMeta: v1.ObjectMeta{
				Namespace: "test",
			},
		},
	}
	require.NoError(t, applyAnnotations(r, ic))

	for name, keys := range map[string][]string{
		"tls_custom_ca_secret":            {model.CAKey},
		"tls_downstream_client_ca_secret": {model.CAKey},
		"tls_client_secret":               {corev1.TLSCertKey, corev1.TLSPrivateKeyKey},
	} {
		ic.Ingress.Annotations = map[string]string{
			fmt.Sprintf("%s/%s", ic.AnnotationPrefix, name): name,
		}
		for _, testKey := range keys {
			data := make(map[string][]byte)
			ic.Secrets = map[types.NamespacedName]*corev1.Secret{
				{Name: name, Namespace: "test"}: {Data: data},
			}
			for _, key := range keys {
				if key == testKey {
					continue
				}
				data[key] = []byte("data")
			}
			assert.Errorf(t, applyAnnotations(r, ic), "name=%s key=%s", name, testKey)
		}
	}
}

func TestYaml(t *testing.T) {
	for input, expect := range map[string]interface{}{
		"10":                                10,
		"0.5":                               0.5,
		"true":                              true,
		"text":                              "text",
		"'text2'":                           "text2",
		`{"bool_key":true}`:                 map[string]interface{}{"bool_key": true},
		`{"groups":["admin", "superuser"]}`: map[string]interface{}{"groups": []interface{}{"admin", "superuser"}},
		`groups: ["admin", "superuser"]`:    map[string]interface{}{"groups": []interface{}{"admin", "superuser"}},
	} {
		var out interface{}
		if assert.NoError(t, yaml.Unmarshal([]byte(input), &out), input) {
			assert.Equal(t, expect, out)
		}
	}
}
