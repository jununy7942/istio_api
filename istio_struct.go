package istio_api

import (
	"google.golang.org/protobuf/proto"
	networking "istio.io/api/networking/v1alpha3"
	security "istio.io/api/security/v1beta1"
)

type St_port struct {
	Number   uint32
	Name     string
	Protocol string
}

type St_endpoints struct {
	Address string
	Ports   St_port
}

type St_match_header struct {
	Header string
	Value  string
}

type St_http_retry struct {
	Attempts      int32
	RetryOn       string
	Pertrytimeout int64
}

type St_header_option struct {
	Set map[string]string
	Add map[string]string
}

type St_http_route_headers struct {
	Response St_header_option
}

type St_http_route_dest struct {
	Host   string
	Subset string
	Port   St_port
}

type St_http_route struct {
	Http_route_dest    St_http_route_dest
	Weight             int32
	Http_route_headers St_http_route_headers
}

type St_http_rewrite struct {
	Authority string
}

type St_http_match struct {
	Httpmatchuriprefix    []string
	Httpmatchheaderprefix St_match_header
}

type St_tls struct {
	Tls_mod networking.ServerTLSSettings_TLSmode
	Tls_sc  string
	Tls_pk  string
	Tls_cc  string
	Tls_cn  string
}

type St_gw_server struct {
	Port  St_port
	Hosts []string
	Tls   St_tls
}

type St_dr_traffic_policy struct {
	//dr_tp_lb_simple int32
	Dr_tp_lb_simple networking.LoadBalancerSettings_SimpleLB
	Max_conn        int32
	//max_http2_req     int32
	//max_req_per_conn  int32
	Consecutive_err   int32
	Interval          int32
	Base_eject_time   int32
	Max_eject_percent int32
}

type St_subset struct {
	Name           string
	Labels         map[string]string
	Traffic_policy St_dr_traffic_policy
}

type St_http struct {
	Httpmatch   []St_http_match
	Httproute   []St_http_route
	Httprewrite St_http_rewrite
	Httptimeout int64
	Httpretry   St_http_retry
}

type St_gw_info struct {
	Gw_name     string
	Gw_selector map[string]string
	Gw_servers  []St_gw_server
}

type St_dr_info struct {
	Dr_name   string
	Dr_host   string
	Dr_subset []St_subset
	//dr_tp_lb_simple int32
	Dr_tp_lb_simple networking.LoadBalancerSettings_SimpleLB
}

type St_vs_info struct {
	Vs_name      string
	Vs_hosts     []string
	Vs_gate_ways []string
	Vs_http      []St_http
}

type St_se_info struct {
	Se_name       string
	Se_location   networking.ServiceEntry_Location
	Se_endpoints  []St_endpoints
	Se_hosts      []string
	Se_resolution networking.ServiceEntry_Resolution
	Se_ports      []St_port
}

type St_ef_info struct {
	Ef_name              string
	Ef_filter_name       string
	Ef_filter_type       string
	Ef_applyto           networking.EnvoyFilter_ApplyTo
	Ef_proto             proto.Message
	Ef_filter_chain_name string
	Ef_filter_subname    string
	Ef_operation         networking.EnvoyFilter_Patch_Operation
}

type St_pa_info struct {
	Pa_name        string
	Pa_match_label map[string]string
	Pa_mtls_mode   security.PeerAuthentication_MutualTLS_Mode
	Pa_port_mtls   map[uint32]security.PeerAuthentication_MutualTLS_Mode
}

type St_proxy_info struct {
	Proxy_id      string
	Pod_name      string
	Namespace     string
	Istio_version string
	Cds           string
	Lds           string
	Rds           string
	Eds           string
}

/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
