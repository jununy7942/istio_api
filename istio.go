package istio_api

import (
	"bytes"
	"context"
	"encoding/json"
	"scp-ctrl/common/util"
	"strings"
	"time"

	scpfilterext "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/scp/v3"
	gogojsonpb "github.com/gogo/protobuf/jsonpb"
	"github.com/gogo/protobuf/types"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	apitypev1beta1 "istio.io/api/type/v1beta1"

	gogoTypes "github.com/gogo/protobuf/types"
	networkingv1alpha3 "istio.io/api/networking/v1alpha3"
	secv1beta1 "istio.io/api/security/v1beta1"
	apinetv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	apisecv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	versionedclient "istio.io/client-go/pkg/clientset/versioned"
	"istio.io/istio/istioctl/pkg/clioptions"
	"istio.io/istio/pilot/pkg/xds"
	"istio.io/istio/pkg/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	//networkingclient "istio.io/client-go/pkg/clientset/versioned/typed/networking/v1alpha3"
)

type Obj_IstioCmd struct {
	client_set     *versionedclient.Clientset
	ext_client_set kube.ExtendedClient
}

type sidecarSyncStatus struct {
	// nolint: structcheck, unused
	pilot string
	xds.SyncStatus
}

func Set_IstioCmdInstance(configBytes []byte) *Obj_IstioCmd {
	obj_instance := new(Obj_IstioCmd)

	obj_cluster_cfg, obj_ret := clientcmd.RESTConfigFromKubeConfig(configBytes)
	if obj_ret != nil {
		util.LOG_ERR("[INIT_POD] clientcmd.RESTConfigFromKubeConfig() %s failed", obj_ret.Error())
		return nil
	}

	obj_instance.client_set, obj_ret = versionedclient.NewForConfig(obj_cluster_cfg)
	if obj_ret != nil {
		util.LOG_ERR("Failed to create istio client: %s", obj_ret.Error())
		return nil
	}

	obj_client_cfg, obj_ret := clientcmd.NewClientConfigFromBytes(configBytes)
	if obj_ret != nil {
		util.LOG_ERR("[INIT_POD] clientcmd.NewClientConfigFromBytes() %s failed", obj_ret.Error())
		return nil
	}

	var opts clioptions.ControlPlaneOptions
	obj_instance.ext_client_set, obj_ret = kube.NewExtendedClient(obj_client_cfg, opts.Revision)
	if obj_ret != nil {
		util.LOG_ERR("Failed to NewExtendedClient: %s", obj_ret.Error())
		return nil
	}

	return obj_instance
}

func Set_IstioCmdInstance_config(obj_cluster_cfg *rest.Config, kubeconfig string) *Obj_IstioCmd {
	var obj_ret error = nil

	obj_instance := new(Obj_IstioCmd)

	obj_instance.client_set, obj_ret = versionedclient.NewForConfig(obj_cluster_cfg)
	if obj_ret != nil {
		util.LOG_ERR("Failed to NewForConfig: %s", obj_ret.Error())
		return nil
	}

	var opts clioptions.ControlPlaneOptions
	var configContext string
	obj_instance.ext_client_set, obj_ret = kube.NewExtendedClient(kube.BuildClientCmd(kubeconfig, configContext), opts.Revision)
	if obj_ret != nil {
		util.LOG_ERR("Failed to NewExtendedClient: %s", obj_ret.Error())
		return nil
	}

	return obj_instance
}

func (obj_istio_cmd *Obj_IstioCmd) GetProxyInfo(namespace string) (*[]St_proxy_info, error) {
	// Ask Pilot for the Envoy sidecar sync status, which includes the sidecar version info
	allSyncz, err := obj_istio_cmd.ext_client_set.AllDiscoveryDo(context.TODO(), namespace, "/debug/syncz") // namespace: istio-system
	if err != nil {
		util.LOG_ERR("Failed to AllDiscoveryDo")
		return nil, err
	}

	pis := []St_proxy_info{}

	for _, syncz := range allSyncz {
		var sss []*sidecarSyncStatus
		err = json.Unmarshal(syncz, &sss)
		if err != nil {
			util.LOG_ERR("Failed to Unmarshal")
			return nil, err
		}

		for _, ss := range sss {
			var pi St_proxy_info
			pi.Proxy_id = ss.ProxyID
			pi.Istio_version = ss.SyncStatus.IstioVersion
			if ss.SyncStatus.ClusterSent == "" && ss.SyncStatus.ClusterAcked == "" {
				pi.Cds = "NOT SENT"
			} else if ss.SyncStatus.ClusterSent == ss.SyncStatus.ClusterAcked {
				pi.Cds = "SYNCED"
			} else {
				pi.Cds = "STALE"
			}
			if ss.SyncStatus.ListenerSent == "" && ss.SyncStatus.ListenerAcked == "" {
				pi.Lds = "NOT SENT"
			} else if ss.SyncStatus.ListenerSent == ss.SyncStatus.ListenerAcked {
				pi.Lds = "SYNCED"
			} else {
				pi.Lds = "STALE"
			}
			if ss.SyncStatus.RouteSent == "" && ss.SyncStatus.RouteAcked == "" {
				pi.Rds = "NOT SENT"
			} else if ss.SyncStatus.RouteSent == ss.SyncStatus.RouteAcked {
				pi.Rds = "SYNCED"
			} else {
				pi.Rds = "STALE"
			}
			if ss.SyncStatus.EndpointSent == "" && ss.SyncStatus.EndpointAcked == "" {
				pi.Eds = "NOT SENT"
			} else if ss.SyncStatus.EndpointSent == ss.SyncStatus.EndpointAcked {
				pi.Eds = "SYNCED"
			} else {
				pi.Eds = "STALE"
			}

			proxy_ids := strings.Split(pi.Proxy_id, ".")
			if len(proxy_ids) != 2 {
				continue
			}
			pi.Pod_name = proxy_ids[0]
			pi.Namespace = proxy_ids[1]

			pis = append(pis, pi)
		}
	}

	return &pis, nil
}

//func (obj_istio_cmd *Obj_IstioCmd) Destroy() {
//	return
//}

func (obj_istio_cmd *Obj_IstioCmd) Add_vs(namespace string, vs_info St_vs_info) bool {
	var err error

	var http []*networkingv1alpha3.HTTPRoute

	for _, vs_http := range vs_info.Vs_http {
		var matchs []*networkingv1alpha3.HTTPMatchRequest
		var route []*networkingv1alpha3.HTTPRouteDestination

		for _, http_match := range vs_http.Httpmatch {
			var match networkingv1alpha3.HTTPMatchRequest
			/* PREFIX */
			for _, vs_prefix := range http_match.Httpmatchuriprefix {
				if len(vs_prefix) > 0 {
					match.Uri = &networkingv1alpha3.StringMatch{
						MatchType: &networkingv1alpha3.StringMatch_Prefix{
							Prefix: vs_prefix,
						},
					}
				}
			}

			// Header  EXACT
			if len(http_match.Httpmatchheaderprefix.Header) > 0 && len(http_match.Httpmatchheaderprefix.Value) > 0 {
				match.Headers = map[string]*networkingv1alpha3.StringMatch{
					http_match.Httpmatchheaderprefix.Header: {
						MatchType: &networkingv1alpha3.StringMatch_Prefix{
							Prefix: http_match.Httpmatchheaderprefix.Value,
						},
					},
				}
			}
			matchs = append(matchs, &match)
		}

		/* ROUTE */
		for _, vs_route := range vs_http.Httproute {
			var route_destination *networkingv1alpha3.HTTPRouteDestination
			var destination networkingv1alpha3.Destination

			destination.Host = vs_route.Http_route_dest.Host
			destination.Subset = vs_route.Http_route_dest.Subset
			if vs_route.Http_route_dest.Port.Number > 0 {
				destination.Port = &networkingv1alpha3.PortSelector{
					Number: vs_route.Http_route_dest.Port.Number,
				}
			}

			route_destination = &networkingv1alpha3.HTTPRouteDestination{
				Destination: &destination,
				Weight:      vs_route.Weight,
			}

			if len(vs_route.Http_route_headers.Response.Add) > 0 {
				route_destination.Headers = &networkingv1alpha3.Headers{
					Response: &networkingv1alpha3.Headers_HeaderOperations{
						Add: vs_route.Http_route_headers.Response.Add,
					},
				}
			}

			route = append(route, route_destination)
		}

		http_route := &networkingv1alpha3.HTTPRoute{
			Match:   matchs,
			Route:   route,
			Timeout: gogoTypes.DurationProto(time.Second * time.Duration(vs_http.Httptimeout)),
			Retries: &networkingv1alpha3.HTTPRetry{
				Attempts:      vs_http.Httpretry.Attempts,
				RetryOn:       vs_http.Httpretry.RetryOn,
				PerTryTimeout: gogoTypes.DurationProto(time.Millisecond * time.Duration(vs_http.Httpretry.Pertrytimeout)),
			},
		}
		if vs_http.Httprewrite.Authority != "" {
			http_route.Rewrite = &networkingv1alpha3.HTTPRewrite{
				Authority: vs_http.Httprewrite.Authority,
			}
		}

		http = append(http, http_route)
	}

	spec := networkingv1alpha3.VirtualService{
		Hosts:    vs_info.Vs_hosts,
		Gateways: vs_info.Vs_gate_ways,
		Http:     http,
	}

	vs_create := &apinetv1alpha3.VirtualService{
		ObjectMeta: metav1.ObjectMeta{
			Name: vs_info.Vs_name,
		},
		Spec: spec,
	}

	vs_create, err = obj_istio_cmd.client_set.NetworkingV1alpha3().VirtualServices(namespace).Create(context.TODO(), vs_create, metav1.CreateOptions{})
	if err != nil {
		util.LOG_ERR("Failed to create VirtualService in %s namespace: %s, info: %v", namespace, err.Error(), vs_info)
		util.LOG_DBG("%+v", vs_info)
		return false
	}

	util.LOG_DBG("create VirtualService name: %+v", vs_create.ObjectMeta.Name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Upd_vs(namespace string, vs_info St_vs_info) bool {
	var err error
	var http []*networkingv1alpha3.HTTPRoute

	vs_update, err := obj_istio_cmd.client_set.NetworkingV1alpha3().VirtualServices(namespace).Get(context.TODO(), vs_info.Vs_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get VirtualService in %s namespace, %s: %s", namespace, vs_info.Vs_name, err.Error())
		return false
	}

	for _, vs_http := range vs_info.Vs_http {
		var matchs []*networkingv1alpha3.HTTPMatchRequest
		var route []*networkingv1alpha3.HTTPRouteDestination

		for _, http_match := range vs_http.Httpmatch {
			var match networkingv1alpha3.HTTPMatchRequest
			/* PREFIX */
			for _, vs_prefix := range http_match.Httpmatchuriprefix {
				if len(vs_prefix) > 0 {
					match.Uri = &networkingv1alpha3.StringMatch{
						MatchType: &networkingv1alpha3.StringMatch_Prefix{
							Prefix: vs_prefix,
						},
					}
				}
			}

			// Header  EXACT
			if len(http_match.Httpmatchheaderprefix.Header) > 0 && len(http_match.Httpmatchheaderprefix.Value) > 0 {
				match.Headers = map[string]*networkingv1alpha3.StringMatch{
					http_match.Httpmatchheaderprefix.Header: {
						MatchType: &networkingv1alpha3.StringMatch_Prefix{
							Prefix: http_match.Httpmatchheaderprefix.Value,
						},
					},
				}
			}
			matchs = append(matchs, &match)
		}
		//util.LOG_ERR("TEST %v", matchs)

		/* ROUTE */
		for _, vs_route := range vs_http.Httproute {
			var route_destination *networkingv1alpha3.HTTPRouteDestination
			var destination networkingv1alpha3.Destination

			destination.Host = vs_route.Http_route_dest.Host
			destination.Subset = vs_route.Http_route_dest.Subset
			if vs_route.Http_route_dest.Port.Number > 0 {
				destination.Port = &networkingv1alpha3.PortSelector{
					Number: vs_route.Http_route_dest.Port.Number,
				}
			}

			route_destination = &networkingv1alpha3.HTTPRouteDestination{
				Destination: &destination,
				Weight:      vs_route.Weight,
			}

			if len(vs_route.Http_route_headers.Response.Add) > 0 {
				route_destination.Headers = &networkingv1alpha3.Headers{
					Response: &networkingv1alpha3.Headers_HeaderOperations{
						Add: vs_route.Http_route_headers.Response.Add,
					},
				}
			}
			route = append(route, route_destination)
		}

		http_route := &networkingv1alpha3.HTTPRoute{
			Match:   matchs,
			Route:   route,
			Timeout: gogoTypes.DurationProto(time.Second * time.Duration(vs_http.Httptimeout)),
			Retries: &networkingv1alpha3.HTTPRetry{
				Attempts:      vs_http.Httpretry.Attempts,
				RetryOn:       vs_http.Httpretry.RetryOn,
				PerTryTimeout: gogoTypes.DurationProto(time.Millisecond * time.Duration(vs_http.Httpretry.Pertrytimeout)),
			},
		}
		if vs_http.Httprewrite.Authority != "" {
			http_route.Rewrite = &networkingv1alpha3.HTTPRewrite{
				Authority: vs_http.Httprewrite.Authority,
			}
		}

		http = append(http, http_route)
	}

	spec := networkingv1alpha3.VirtualService{
		Hosts:    vs_info.Vs_hosts,
		Gateways: vs_info.Vs_gate_ways,
		Http:     http,
	}

	vs_update.Spec = spec

	vs_update, err = obj_istio_cmd.client_set.NetworkingV1alpha3().VirtualServices(namespace).Update(context.TODO(), vs_update, metav1.UpdateOptions{})
	if err != nil {
		util.LOG_ERR("Failed to update VirtualService in %s namespace: %s, info: %v", namespace, err.Error(), vs_info)
		return false
	}

	util.LOG_DBG("update VirtualService name: %+v", vs_update.ObjectMeta.Name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Del_vs(namespace string, vs_name string) bool {
	err := obj_istio_cmd.client_set.NetworkingV1alpha3().VirtualServices(namespace).Delete(context.TODO(), vs_name, metav1.DeleteOptions{})
	if err != nil {
		util.LOG_ERR("Failed to delete VirtualService in %s namespace, %s: %s", namespace, vs_name, err.Error())
		return false
	}
	util.LOG_DBG("delete VirtualService name: %+v", vs_name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) List_vs(namespace string) {
	vsList, err := obj_istio_cmd.client_set.NetworkingV1alpha3().VirtualServices(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		util.LOG_ERR("Failed to get VirtualService in %s namespace: %s", namespace, err.Error())
	}

	for i := range vsList.Items {
		vs := vsList.Items[i]
		util.LOG_DBG("Index: %d VirtualService Name: %+v", i, vs.ObjectMeta.Name)
	}
}

func (obj_istio_cmd *Obj_IstioCmd) Is_vs(namespace string, vs_name string) bool {
	_, err := obj_istio_cmd.client_set.NetworkingV1alpha3().VirtualServices(namespace).Get(context.TODO(), vs_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Not exist VirtualService in %s namespace, %s: %s", namespace, vs_name, err.Error())
		return false
	}

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Get_vs(namespace string, vs_name string, vs_info *St_vs_info) bool {
	vs, err := obj_istio_cmd.client_set.NetworkingV1alpha3().VirtualServices(namespace).Get(context.TODO(), vs_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get VirtualService in %s namespace, %s: %s", namespace, vs_name, err.Error())
		return false
	}
	//util.LOG_DBG("BEFORE VirtualService %v", vs_info)

	*vs_info = St_vs_info{}

	vs_info.Vs_name = vs.ObjectMeta.Name
	vs_info.Vs_hosts = vs.Spec.Hosts
	vs_info.Vs_gate_ways = vs.Spec.Gateways

	for _, http := range vs.Spec.Http {
		//var exact, prefix, regex []string
		var prefix string
		var http_route []St_http_route
		var match_header St_match_header
		var http_matchs []St_http_match
		//var header map[string]string
		//header = make(map[string]string)

		for _, match := range http.Match {
			if x, ok := match.Uri.GetMatchType().(*networkingv1alpha3.StringMatch_Prefix); ok {
				prefix = x.Prefix
			}

			for key, h := range match.GetHeaders() {
				match_header.Header = key
				match_header.Value = h.GetPrefix()
			}

			http_match := St_http_match{[]string{prefix}, match_header}
			http_matchs = append(http_matchs, http_match)
		}

		for _, route := range http.Route {
			http_route_dest := St_http_route_dest{route.Destination.Host, route.Destination.Subset, St_port{}}
			if route.Destination.Port != nil {
				http_route_dest.Port = St_port{route.Destination.Port.Number, "", ""}
			}

			var http_route_headers St_http_route_headers

			headers := route.GetHeaders()
			if headers != nil {
				response := headers.GetResponse()
				if response != nil {
					if len(response.Add) > 0 {
						http_route_headers.Response.Add = response.Add
					}
				}
			}

			tmp := St_http_route{Http_route_dest: http_route_dest, Weight: route.Weight, Http_route_headers: http_route_headers}

			http_route = append(http_route, tmp)
		}
		var per_try_timeout int64
		if http.Retries.GetPerTryTimeout().GetNanos() > 0 {
			per_try_timeout = int64(http.Retries.GetPerTryTimeout().GetNanos() / 1000000)
			//util.LOG_ERR("PerTryTimeout: %d", per_try_timeout)
		} else {
			per_try_timeout = 500
		}
		http_retry := St_http_retry{http.Retries.Attempts, http.Retries.RetryOn, per_try_timeout}

		http_rewrite := St_http_rewrite{http.Rewrite.Authority}

		tmp := St_http{http_matchs, http_route, http_rewrite, http.Timeout.GetSeconds(), http_retry}
		vs_info.Vs_http = append(vs_info.Vs_http, tmp)
	}
	//util.LOG_DBG("AFTER VirtualService %v", vs_info)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Add_gw(namespace string, gw_info St_gw_info) bool {
	var err error
	var servers []*networkingv1alpha3.Server

	for _, gw_server := range gw_info.Gw_servers {
		port := &networkingv1alpha3.Port{
			Number:   uint32(gw_server.Port.Number),
			Name:     gw_server.Port.Name,
			Protocol: gw_server.Port.Protocol,
		}

		var tls *networkingv1alpha3.ServerTLSSettings

		if gw_server.Tls.Tls_mod != networkingv1alpha3.ServerTLSSettings_PASSTHROUGH {
			tls = &networkingv1alpha3.ServerTLSSettings{
				Mode:              gw_server.Tls.Tls_mod,
				ServerCertificate: gw_server.Tls.Tls_sc,
				PrivateKey:        gw_server.Tls.Tls_pk,
				CaCertificates:    gw_server.Tls.Tls_cc,
				CredentialName:    gw_server.Tls.Tls_cn,
			}
		}

		server := &networkingv1alpha3.Server{
			Port:  port,
			Hosts: gw_server.Hosts,
			Tls:   tls,
		}

		servers = append(servers, server)
	}

	spec := networkingv1alpha3.Gateway{
		Servers:  servers,
		Selector: gw_info.Gw_selector,
	}

	gw_create := &apinetv1alpha3.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: gw_info.Gw_name,
		},
		Spec: spec,
	}

	gw_create, err = obj_istio_cmd.client_set.NetworkingV1alpha3().Gateways(namespace).Create(context.TODO(), gw_create, metav1.CreateOptions{})
	if err != nil {
		util.LOG_ERR("Failed to create Gateway in %s namespace: %s, info: %v", namespace, err.Error(), gw_info)
		return false
	}

	util.LOG_DBG("create gateway name: %+v", gw_create.ObjectMeta.Name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Upd_gw(namespace string, gw_info St_gw_info) bool {
	var err error

	var servers []*networkingv1alpha3.Server

	gw_update, err := obj_istio_cmd.client_set.NetworkingV1alpha3().Gateways(namespace).Get(context.TODO(), gw_info.Gw_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get Gateway in %s namespace, %s: %s", namespace, gw_info.Gw_name, err.Error())
		return false
	}

	for _, gw_server := range gw_info.Gw_servers {
		port := &networkingv1alpha3.Port{
			Number:   uint32(gw_server.Port.Number),
			Name:     gw_server.Port.Name,
			Protocol: gw_server.Port.Protocol,
		}

		var tls *networkingv1alpha3.ServerTLSSettings

		if gw_server.Tls.Tls_mod != networkingv1alpha3.ServerTLSSettings_PASSTHROUGH {
			tls = &networkingv1alpha3.ServerTLSSettings{
				Mode:              gw_server.Tls.Tls_mod,
				ServerCertificate: gw_server.Tls.Tls_sc,
				PrivateKey:        gw_server.Tls.Tls_pk,
				CaCertificates:    gw_server.Tls.Tls_cc,
				CredentialName:    gw_server.Tls.Tls_cn,
			}
		}

		server := &networkingv1alpha3.Server{
			Port:  port,
			Hosts: gw_server.Hosts,
			Tls:   tls,
		}

		servers = append(servers, server)
	}

	spec := networkingv1alpha3.Gateway{
		Servers:  servers,
		Selector: gw_info.Gw_selector,
	}

	gw_update.Spec = spec

	gw_update, err = obj_istio_cmd.client_set.NetworkingV1alpha3().Gateways(namespace).Update(context.TODO(), gw_update, metav1.UpdateOptions{})
	if err != nil {
		util.LOG_ERR("Failed to update Gateway in %s namespace: %s, info: %v", namespace, err.Error(), gw_info)
		return false
	}

	util.LOG_DBG("update gateway name: %+v", gw_update.ObjectMeta.Name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Del_gw(namespace string, gw_name string) bool {

	err := obj_istio_cmd.client_set.NetworkingV1alpha3().Gateways(namespace).Delete(context.TODO(), gw_name, metav1.DeleteOptions{})
	if err != nil {
		util.LOG_ERR("Failed to delete Gateway in %s namespace, %s: %s", namespace, gw_name, err.Error())
		return false
	}
	util.LOG_DBG("delete Gateway name: %+v", gw_name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) List_gw(namespace string) {
	gwList, err := obj_istio_cmd.client_set.NetworkingV1alpha3().Gateways(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		util.LOG_ERR("Failed to get Gateway in %s namespace: %s", namespace, err.Error())
	}

	for i := range gwList.Items {
		gw := gwList.Items[i]
		util.LOG_DBG("Index: %d Gateway Name: %+v", i, gw.ObjectMeta.Name)
	}

	return
}

func (obj_istio_cmd *Obj_IstioCmd) Is_gw(namespace string, gw_name string) bool {
	_, err := obj_istio_cmd.client_set.NetworkingV1alpha3().Gateways(namespace).Get(context.TODO(), gw_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Not exist Gateway in %s namespace, %s: %s", namespace, gw_name, err.Error())
		return false
	}

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Get_gw(namespace string, gw_name string, gw_info *St_gw_info) bool {
	gw, err := obj_istio_cmd.client_set.NetworkingV1alpha3().Gateways(namespace).Get(context.TODO(), gw_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get Gateway in %s namespace, %s: %s", namespace, gw_name, err.Error())
		return false
	}
	//util.LOG_DBG("BEFORE Gateway %v", gw_info)

	*gw_info = St_gw_info{}

	gw_info.Gw_name = gw.ObjectMeta.Name
	gw_info.Gw_selector = gw.Spec.Selector

	var servers []St_gw_server

	for _, gw_server := range gw.Spec.Servers {
		port := St_port{gw_server.Port.Number, gw_server.Port.Name, gw_server.Port.Protocol}

		tls := St_tls{Tls_mod: gw_server.Tls.Mode, Tls_sc: gw_server.Tls.ServerCertificate,
			Tls_pk: gw_server.Tls.PrivateKey, Tls_cc: gw_server.Tls.CaCertificates, Tls_cn: gw_server.Tls.CredentialName}

		server := St_gw_server{port, gw_server.Hosts, tls}

		servers = append(servers, server)
	}

	gw_info.Gw_servers = servers

	//util.LOG_DBG("AFTER Gateway %v", gw_info)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Add_dr(namespace string, dr_info St_dr_info) bool {
	var err error

	var subsets []*networkingv1alpha3.Subset

	for _, dr_subset := range dr_info.Dr_subset {
		trafficpolicy := &networkingv1alpha3.TrafficPolicy{
			LoadBalancer: &networkingv1alpha3.LoadBalancerSettings{
				LbPolicy: &networkingv1alpha3.LoadBalancerSettings_Simple{
					//Simple: networkingv1alpha3.LoadBalancerSettings_ROUND_ROBIN,
					Simple: dr_subset.Traffic_policy.Dr_tp_lb_simple,
				},
			},
			ConnectionPool: &networkingv1alpha3.ConnectionPoolSettings{
				Tcp: &networkingv1alpha3.ConnectionPoolSettings_TCPSettings{
					MaxConnections: dr_subset.Traffic_policy.Max_conn,
				},
				//Http: &networkingv1alpha3.ConnectionPoolSettings_HTTPSettings{
				//	Http2MaxRequests:         dr_subset.Traffic_policy.Max_http2_req,
				//	MaxRequestsPerConnection: dr_subset.Traffic_policy.Max_req_per_conn,
				//},
			},
			OutlierDetection: &networkingv1alpha3.OutlierDetection{
				ConsecutiveErrors:  dr_subset.Traffic_policy.Consecutive_err,
				Interval:           gogoTypes.DurationProto(time.Second * time.Duration(dr_subset.Traffic_policy.Interval)),
				BaseEjectionTime:   gogoTypes.DurationProto(time.Millisecond * time.Duration(dr_subset.Traffic_policy.Base_eject_time)),
				MaxEjectionPercent: dr_subset.Traffic_policy.Max_eject_percent,
			},
		}

		subset := &networkingv1alpha3.Subset{
			Name:          dr_subset.Name,
			Labels:        dr_subset.Labels,
			TrafficPolicy: trafficpolicy,
		}
		subsets = append(subsets, subset)
	}

	spec := networkingv1alpha3.DestinationRule{
		Host:    dr_info.Dr_host,
		Subsets: subsets,
	}

	dr_create := &apinetv1alpha3.DestinationRule{
		ObjectMeta: metav1.ObjectMeta{
			Name: dr_info.Dr_name,
		},
		Spec: spec,
	}

	dr_create, err = obj_istio_cmd.client_set.NetworkingV1alpha3().DestinationRules(namespace).Create(context.TODO(), dr_create, metav1.CreateOptions{})
	if err != nil {
		util.LOG_ERR("Failed to create DestinationRule in %s namespace: %s, info: %v", namespace, err.Error(), dr_info)
		return false
	}
	util.LOG_DBG("create DestinationRule name: %+v", dr_create.ObjectMeta.Name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Upd_dr(namespace string, dr_info St_dr_info) bool {
	var err error

	var subsets []*networkingv1alpha3.Subset

	dr_update, err := obj_istio_cmd.client_set.NetworkingV1alpha3().DestinationRules(namespace).Get(context.TODO(), dr_info.Dr_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get DestinationRule in %s namespace, %s: %s", namespace, dr_info.Dr_name, err.Error())
		return false
	}

	for _, dr_subset := range dr_info.Dr_subset {
		trafficpolicy := &networkingv1alpha3.TrafficPolicy{
			LoadBalancer: &networkingv1alpha3.LoadBalancerSettings{
				LbPolicy: &networkingv1alpha3.LoadBalancerSettings_Simple{
					//Simple: networkingv1alpha3.LoadBalancerSettings_ROUND_ROBIN,
					Simple: dr_subset.Traffic_policy.Dr_tp_lb_simple,
				},
			},
			ConnectionPool: &networkingv1alpha3.ConnectionPoolSettings{
				Tcp: &networkingv1alpha3.ConnectionPoolSettings_TCPSettings{
					MaxConnections: dr_subset.Traffic_policy.Max_conn,
				},
				//Http: &networkingv1alpha3.ConnectionPoolSettings_HTTPSettings{
				//	Http2MaxRequests:         dr_subset.Traffic_policy.Max_http2_req,
				//	MaxRequestsPerConnection: dr_subset.Traffic_policy.Max_req_per_conn,
				//},
			},
			OutlierDetection: &networkingv1alpha3.OutlierDetection{
				ConsecutiveErrors:  dr_subset.Traffic_policy.Consecutive_err,
				Interval:           gogoTypes.DurationProto(time.Second * time.Duration(dr_subset.Traffic_policy.Interval)),
				BaseEjectionTime:   gogoTypes.DurationProto(time.Millisecond * time.Duration(dr_subset.Traffic_policy.Base_eject_time)),
				MaxEjectionPercent: dr_subset.Traffic_policy.Max_eject_percent,
			},
		}

		subset := &networkingv1alpha3.Subset{
			Name:          dr_subset.Name,
			Labels:        dr_subset.Labels,
			TrafficPolicy: trafficpolicy,
		}
		subsets = append(subsets, subset)
	}

	spec := networkingv1alpha3.DestinationRule{
		Host:    dr_info.Dr_host,
		Subsets: subsets,
	}

	dr_update.Spec = spec

	dr_update, err = obj_istio_cmd.client_set.NetworkingV1alpha3().DestinationRules(namespace).Update(context.TODO(), dr_update, metav1.UpdateOptions{})
	if err != nil {
		util.LOG_ERR("Failed to update DestinationRule in %s namespace: %s, info: %v", namespace, err.Error(), dr_info)
		return false
	}
	util.LOG_DBG("update DestinationRule name: %+v", dr_update.ObjectMeta.Name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Is_dr(namespace string, dr_name string) bool {
	_, err := obj_istio_cmd.client_set.NetworkingV1alpha3().DestinationRules(namespace).Get(context.TODO(), dr_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Not exist DestinationRule in %s namespace, %s: %s", namespace, dr_name, err.Error())
		return false
	}

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Get_dr(namespace string, dr_name string, dr_info *St_dr_info) bool {
	dr, err := obj_istio_cmd.client_set.NetworkingV1alpha3().DestinationRules(namespace).Get(context.TODO(), dr_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get DestinationRule in %s namespace, %s: %s", namespace, dr_name, err.Error())
		return false
	}
	//util.LOG_DBG("BEFORE DestinationRule %v", dr_info)

	*dr_info = St_dr_info{}

	dr_info.Dr_name = dr.ObjectMeta.Name
	dr_info.Dr_host = dr.Spec.Host

	var subsets []St_subset

	for _, subset := range dr.Spec.Subsets {
		var traffic_policy St_dr_traffic_policy

		if subset.TrafficPolicy != nil {
			if x, ok := subset.TrafficPolicy.LoadBalancer.GetLbPolicy().(*networkingv1alpha3.LoadBalancerSettings_Simple); ok {
				traffic_policy.Dr_tp_lb_simple = x.Simple
			}

			traffic_policy.Max_conn = subset.TrafficPolicy.ConnectionPool.Tcp.MaxConnections
			//traffic_policy.Max_http2_req = subset.TrafficPolicy.ConnectionPool.Http.Http2MaxRequests
			//traffic_policy.Max_req_per_conn = subset.TrafficPolicy.ConnectionPool.Http.MaxRequestsPerConnection
			traffic_policy.Consecutive_err = subset.TrafficPolicy.OutlierDetection.ConsecutiveErrors
			traffic_policy.Interval = int32(subset.TrafficPolicy.OutlierDetection.GetInterval().GetSeconds())
			if subset.TrafficPolicy.OutlierDetection.GetBaseEjectionTime().GetNanos() > 0 {
				traffic_policy.Base_eject_time = subset.TrafficPolicy.OutlierDetection.GetBaseEjectionTime().GetNanos() / 1000000
			} else {
				traffic_policy.Base_eject_time = 2
			}
			traffic_policy.Max_eject_percent = subset.TrafficPolicy.OutlierDetection.MaxEjectionPercent
		}

		subset := St_subset{subset.Name, subset.Labels, traffic_policy}
		subsets = append(subsets, subset)
	}
	dr_info.Dr_subset = subsets

	if dr.Spec.TrafficPolicy != nil {
		if x, ok := dr.Spec.TrafficPolicy.LoadBalancer.GetLbPolicy().(*networkingv1alpha3.LoadBalancerSettings_Simple); ok {
			dr_info.Dr_tp_lb_simple = x.Simple
		}
	}

	//util.LOG_DBG("AFTER DestinationRule %v", dr_info)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Del_dr(namespace string, dr_name string) bool {

	err := obj_istio_cmd.client_set.NetworkingV1alpha3().DestinationRules(namespace).Delete(context.TODO(), dr_name, metav1.DeleteOptions{})
	if err != nil {
		util.LOG_ERR("Failed to delete DestinationRule in %s namespace, %s: %s", namespace, dr_name, err.Error())
		return false
	}
	util.LOG_DBG("delete DestinationRule name: %+v", dr_name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Add_se(namespace string, se_info St_se_info) bool {
	var err error

	var endpoints []*networkingv1alpha3.WorkloadEntry
	//util.LOG_ERR("TEST: create %+v", se_info)

	for _, se_endpoint := range se_info.Se_endpoints {
		endpoint := &networkingv1alpha3.WorkloadEntry{
			Address: se_endpoint.Address,
			Ports:   map[string]uint32{se_endpoint.Ports.Name: se_endpoint.Ports.Number},
		}
		endpoints = append(endpoints, endpoint)
	}

	var ports []*networkingv1alpha3.Port

	for _, se_port := range se_info.Se_ports {
		port := &networkingv1alpha3.Port{
			Number:   uint32(se_port.Number),
			Name:     se_port.Name,
			Protocol: se_port.Protocol,
		}
		ports = append(ports, port)
	}

	// CREATE
	se_create := &apinetv1alpha3.ServiceEntry{
		ObjectMeta: metav1.ObjectMeta{
			Name: se_info.Se_name,
		},
		Spec: networkingv1alpha3.ServiceEntry{
			Endpoints:  endpoints,
			ExportTo:   []string{"*"},
			Location:   se_info.Se_location,
			Hosts:      se_info.Se_hosts,
			Ports:      ports,
			Resolution: se_info.Se_resolution,
		},
	}

	se_create, err = obj_istio_cmd.client_set.NetworkingV1alpha3().ServiceEntries(namespace).Create(context.TODO(), se_create, metav1.CreateOptions{})
	if err != nil {
		util.LOG_ERR("Failed to create ServiceEntries in %s namespace: %s, info: %v", namespace, err.Error(), se_info)
		return false
	}

	util.LOG_DBG("create ServiceEntries name: %+v", se_create.ObjectMeta.Name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Upd_se(namespace string, se_info St_se_info) bool {
	var err error

	var endpoints []*networkingv1alpha3.WorkloadEntry
	//util.LOG_ERR("TEST: update %+v", se_info)

	se_update, err := obj_istio_cmd.client_set.NetworkingV1alpha3().ServiceEntries(namespace).Get(context.TODO(), se_info.Se_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get DestinationRule in %s namespace, %s: %s", namespace, se_info.Se_name, err.Error())
		return false
	}

	for _, se_endpoint := range se_info.Se_endpoints {
		endpoint := &networkingv1alpha3.WorkloadEntry{
			Address: se_endpoint.Address,
			Ports:   map[string]uint32{se_endpoint.Ports.Name: se_endpoint.Ports.Number},
		}
		endpoints = append(endpoints, endpoint)
	}

	var ports []*networkingv1alpha3.Port

	for _, se_port := range se_info.Se_ports {
		port := &networkingv1alpha3.Port{
			Number:   uint32(se_port.Number),
			Name:     se_port.Name,
			Protocol: se_port.Protocol,
		}
		ports = append(ports, port)
	}

	// UPDATE
	spec := networkingv1alpha3.ServiceEntry{
		Endpoints:  endpoints,
		ExportTo:   []string{"*"},
		Location:   se_info.Se_location,
		Hosts:      se_info.Se_hosts,
		Ports:      ports,
		Resolution: se_info.Se_resolution,
	}

	se_update.Spec = spec

	se_update, err = obj_istio_cmd.client_set.NetworkingV1alpha3().ServiceEntries(namespace).Update(context.TODO(), se_update, metav1.UpdateOptions{})
	if err != nil {
		util.LOG_ERR("Failed to update ServiceEntries in %s namespace: %s, info: %v", namespace, err.Error(), se_info)
		return false
	}

	util.LOG_DBG("update ServiceEntries name: %+v", se_update.ObjectMeta.Name)

	return true

}

func (obj_istio_cmd *Obj_IstioCmd) Is_se(namespace string, se_name string) bool {
	_, err := obj_istio_cmd.client_set.NetworkingV1alpha3().ServiceEntries(namespace).Get(context.TODO(), se_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Not exist ServiceEntries in %s namespace, %s: %s", namespace, se_name, err.Error())
		return false
	}
	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Get_se(namespace string, se_name string, se_info *St_se_info) bool {
	se, err := obj_istio_cmd.client_set.NetworkingV1alpha3().ServiceEntries(namespace).Get(context.TODO(), se_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get DestinationRule in %s namespace, %s: %s", namespace, se_name, err.Error())
		return false
	}
	//util.LOG_DBG("BEFORE ServiceEntries %v", se_info)

	*se_info = St_se_info{}

	se_info.Se_name = se.ObjectMeta.Name
	se_info.Se_hosts = se.Spec.Hosts

	var endpoints []St_endpoints

	for _, se_endpoint := range se.Spec.Endpoints {
		for key, val := range se_endpoint.Ports {
			endpoint := St_endpoints{se_endpoint.Address, St_port{val, key, ""}}
			endpoints = append(endpoints, endpoint)
			break
		}
	}

	se_info.Se_endpoints = endpoints

	for _, port := range se.Spec.Ports {
		se_port := St_port{port.Number, port.Name, port.Protocol}
		se_info.Se_ports = append(se_info.Se_ports, se_port)
	}
	//se_info.Se_ports = St_port{se.Spec.Ports[0].Number, se.Spec.Ports[0].Name, se.Spec.Ports[0].Protocol}

	//se_info.Se_location = int32(se.Spec.Location)
	se_info.Se_location = se.Spec.Location

	se_info.Se_resolution = se.Spec.Resolution

	//util.LOG_DBG("AFTER DestinationRule %v", se_info)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Del_se(namespace string, se_name string) bool {
	err := obj_istio_cmd.client_set.NetworkingV1alpha3().ServiceEntries(namespace).Delete(context.TODO(), se_name, metav1.DeleteOptions{})
	if err != nil {
		util.LOG_ERR("Failed to delete ServiceEntries in %s namespace, %s: %s", namespace, se_name, err.Error())
		return false
	}
	//util.LOG_ERR("TEST delete ServiceEntries name: %+v", se_name)
	util.LOG_DBG("delete ServiceEntries name: %+v", se_name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) List_se(namespace string) *apinetv1alpha3.ServiceEntryList {
	seList, err := obj_istio_cmd.client_set.NetworkingV1alpha3().ServiceEntries(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		util.LOG_ERR("Failed to get ServiceEntries in %s namespace: %s", namespace, err.Error())
	}

	for i := range seList.Items {
		se := seList.Items[i]
		util.LOG_DBG("Index: %d ServiceEntries Name: %+v", i, se.ObjectMeta.Name)
	}

	return seList
}

func (obj_istio_cmd *Obj_IstioCmd) Add_ef(namespace string, ef_info *St_ef_info) bool {

	outboundProxyStruct, err := generateValue(ef_info.Ef_proto, ef_info.Ef_filter_name, ef_info.Ef_filter_type)
	if err != nil {
		util.LOG_ERR("failed to create EnvoyFilter value in %s namespace, %s: %s", namespace, ef_info.Ef_name, err.Error())
		return false
	}

	envoyFilter := generateEnvoyFilter(ef_info.Ef_applyto, ef_info.Ef_filter_chain_name,
		ef_info.Ef_filter_subname, ef_info.Ef_operation, outboundProxyStruct)

	ef_create, err := obj_istio_cmd.client_set.NetworkingV1alpha3().EnvoyFilters(namespace).Create(context.TODO(),
		toEnvoyFilterCRD(namespace, ef_info.Ef_name, envoyFilter), metav1.CreateOptions{})
	if err != nil {
		util.LOG_ERR("failed to create EnvoyFilter in %s namespace, %s: %s", namespace, ef_info.Ef_name, err.Error())
		return false
	}
	util.LOG_DBG("create ServiceEntries name: %+v", ef_create.ObjectMeta.Name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Upd_ef(namespace string, ef_info *St_ef_info) bool {
	_, err := obj_istio_cmd.client_set.NetworkingV1alpha3().EnvoyFilters(namespace).Get(context.TODO(),
		ef_info.Ef_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get Gateway in %s namespace, %s: %s", namespace, ef_info.Ef_name, err.Error())
		return false
	}

	outboundProxyStruct, err := generateValue(ef_info.Ef_proto, ef_info.Ef_filter_name, ef_info.Ef_filter_type)
	if err != nil {
		util.LOG_ERR("failed to create EnvoyFilter value in %s namespace, %s: %s", namespace, ef_info.Ef_name, err.Error())
		return false
	}

	envoyFilter := generateEnvoyFilter(ef_info.Ef_applyto, ef_info.Ef_filter_chain_name,
		ef_info.Ef_filter_subname, ef_info.Ef_operation, outboundProxyStruct)

	ef_create, err := obj_istio_cmd.client_set.NetworkingV1alpha3().EnvoyFilters(namespace).Create(context.TODO(),
		toEnvoyFilterCRD(namespace, ef_info.Ef_name, envoyFilter), metav1.CreateOptions{})
	if err != nil {
		util.LOG_ERR("failed to create EnvoyFilter in %s namespace, %s: %s", namespace, ef_info.Ef_name, err.Error())
		return false
	}
	util.LOG_DBG("create ServiceEntries name: %+v", ef_create.ObjectMeta.Name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Get_ef(namespace string, ef_name string, ef_info *St_ef_info) bool {
	ef, err := obj_istio_cmd.client_set.NetworkingV1alpha3().EnvoyFilters(namespace).Get(context.TODO(), ef_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get EnvoyFilter in %s namespace, %s: %s", namespace, ef_name, err.Error())
		return false
	}

	*ef_info = St_ef_info{}
	ef_info.Ef_name = ef.ObjectMeta.Name
	ef_info.Ef_applyto = ef.Spec.ConfigPatches[0].ApplyTo

	listener := ef.Spec.ConfigPatches[0].Match.GetListener()
	if listener == nil {
		util.LOG_DBG("Failed to get EnvoyFilter in %s namespace, %s", namespace, ef_name)
	}
	ef_info.Ef_filter_chain_name = listener.FilterChain.Filter.Name
	ef_info.Ef_filter_subname = listener.FilterChain.Filter.SubFilter.Name

	ef_info.Ef_operation = ef.Spec.ConfigPatches[0].Patch.Operation

	field := ef.Spec.ConfigPatches[0].Patch.Value.GetFields()
	ef_info.Ef_filter_name = field["name"].GetStringValue()

	typed_config := field["typed_config"].GetStructValue()
	type_field := typed_config.GetFields()
	ef_info.Ef_filter_type = type_field["@type"].GetStringValue()

	delete(type_field, "@type")

	buf := &bytes.Buffer{}
	(&gogojsonpb.Marshaler{OrigName: true}).Marshal(buf, typed_config)

	if buf.Len() > 0 {
		if strings.HasSuffix(ef_info.Ef_filter_type, "R16Inbound") == true {
			pbs := &scpfilterext.R16Inbound{}
			protojson.Unmarshal(buf.Bytes(), pbs)
			ef_info.Ef_proto = pbs

		} else if strings.HasSuffix(ef_info.Ef_filter_type, "R16Outbound") == true {
			pbs := &scpfilterext.R16Outbound{}
			protojson.Unmarshal(buf.Bytes(), pbs)
			ef_info.Ef_proto = pbs
		} else if strings.HasSuffix(ef_info.Ef_filter_type, "R15Gateway") == true {
			pbs := &scpfilterext.R15Gateway{}
			protojson.Unmarshal(buf.Bytes(), pbs)
			ef_info.Ef_proto = pbs
		}
	}

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Del_ef(namespace string, ef_name string) bool {
	err := obj_istio_cmd.client_set.NetworkingV1alpha3().EnvoyFilters(namespace).Delete(context.TODO(), ef_name, metav1.DeleteOptions{})
	if err != nil {
		util.LOG_ERR("Failed to delete EnvoyFilter in %s namespace, %s: %s", namespace, ef_name, err.Error())
		return false
	}
	util.LOG_DBG("delete EnvoyFilter name: %+v", ef_name)

	return true
}

func toEnvoyFilterCRD(namespace string, filterName string, new *networkingv1alpha3.EnvoyFilter) *apinetv1alpha3.EnvoyFilter {
	envoyFilter := &apinetv1alpha3.EnvoyFilter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      filterName,
			Namespace: namespace,
			//Labels: map[string]string{
			//    "manager": "scp-ctrl",
			//},
		},
		Spec: *new,
	}

	return envoyFilter
}

func generateEnvoyFilter(applyto networkingv1alpha3.EnvoyFilter_ApplyTo, FilterChainName string, FilterSubName string,
	operation networkingv1alpha3.EnvoyFilter_Patch_Operation, outboundProxyStruct *types.Struct) *networkingv1alpha3.EnvoyFilter {
	var envoyFilter *networkingv1alpha3.EnvoyFilter
	var outboundProxyPatch *networkingv1alpha3.EnvoyFilter_EnvoyConfigObjectPatch

	outboundProxyPatch = &networkingv1alpha3.EnvoyFilter_EnvoyConfigObjectPatch{
		ApplyTo: applyto,
		Match: &networkingv1alpha3.EnvoyFilter_EnvoyConfigObjectMatch{
			ObjectTypes: &networkingv1alpha3.EnvoyFilter_EnvoyConfigObjectMatch_Listener{
				Listener: &networkingv1alpha3.EnvoyFilter_ListenerMatch{
					FilterChain: &networkingv1alpha3.EnvoyFilter_ListenerMatch_FilterChainMatch{
						Filter: &networkingv1alpha3.EnvoyFilter_ListenerMatch_FilterMatch{
							Name: FilterChainName,
							SubFilter: &networkingv1alpha3.EnvoyFilter_ListenerMatch_SubFilterMatch{
								Name: FilterSubName,
							},
						},
					},
				},
			},
		},
		Patch: &networkingv1alpha3.EnvoyFilter_Patch{
			Operation: operation,
			Value:     outboundProxyStruct,
		},
	}

	envoyFilter = &networkingv1alpha3.EnvoyFilter{ConfigPatches: []*networkingv1alpha3.EnvoyFilter_EnvoyConfigObjectPatch{outboundProxyPatch}}

	return envoyFilter
}

func generateValue(proxy proto.Message, filterName string, filterType string) (*types.Struct, error) {
	var buf []byte
	var err error

	if buf, err = protojson.Marshal(proxy); err != nil {
		return nil, err
	}

	var out = &types.Struct{}
	if err = (&gogojsonpb.Unmarshaler{AllowUnknownFields: false}).Unmarshal(bytes.NewBuffer(buf), out); err != nil {
		return nil, err
	}

	out.Fields["@type"] = &types.Value{
		Kind: &types.Value_StringValue{
			StringValue: filterType,
		},
	}

	return &types.Struct{
		Fields: map[string]*types.Value{
			"name": {
				Kind: &types.Value_StringValue{
					StringValue: filterName,
				},
			},
			"typed_config": {
				Kind: &types.Value_StructValue{StructValue: out},
			},
		},
	}, nil
}

func (obj_istio_cmd *Obj_IstioCmd) Add_pa(namespace string, pa_info *St_pa_info) bool {
	var err error
	var selector *apitypev1beta1.WorkloadSelector
	var mtls *secv1beta1.PeerAuthentication_MutualTLS

	var port_mtls map[uint32]*secv1beta1.PeerAuthentication_MutualTLS
	port_mtls = make(map[uint32]*secv1beta1.PeerAuthentication_MutualTLS)

	selector = &apitypev1beta1.WorkloadSelector{
		MatchLabels: pa_info.Pa_match_label,
	}

	if len(pa_info.Pa_port_mtls) > 0 {
		for port, mode := range pa_info.Pa_port_mtls {
			port_mtls[port] = &secv1beta1.PeerAuthentication_MutualTLS{Mode: mode}
		}
	} else {
		mtls = &secv1beta1.PeerAuthentication_MutualTLS{
			Mode: pa_info.Pa_mtls_mode,
		}
	}

	// CREATE
	pa_create := &apisecv1beta1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{
			Name: pa_info.Pa_name,
		},
		Spec: secv1beta1.PeerAuthentication{
			Selector:      selector,
			Mtls:          mtls,
			PortLevelMtls: port_mtls,
		},
	}

	pa_create, err = obj_istio_cmd.client_set.SecurityV1beta1().PeerAuthentications(namespace).
		Create(context.TODO(), pa_create, metav1.CreateOptions{})
	if err != nil {
		util.LOG_ERR("Failed to create PeerAuthentications in %s namespace: %s, info: %v", namespace, err.Error(), pa_info)
		return false
	}

	util.LOG_DBG("create PeerAuthentications name: %+v", pa_create.ObjectMeta.Name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Upd_pa(namespace string, pa_info *St_pa_info) bool {
	var err error
	var selector *apitypev1beta1.WorkloadSelector
	var mtls *secv1beta1.PeerAuthentication_MutualTLS

	var port_mtls map[uint32]*secv1beta1.PeerAuthentication_MutualTLS

	pa_update, err := obj_istio_cmd.client_set.SecurityV1beta1().PeerAuthentications(namespace).Get(context.TODO(),
		pa_info.Pa_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get PeerAuthentications in %s namespace, %s: %s", namespace, pa_info.Pa_name, err.Error())
		return false
	}

	selector = &apitypev1beta1.WorkloadSelector{
		MatchLabels: pa_info.Pa_match_label,
	}

	if len(pa_info.Pa_port_mtls) > 0 {
		port_mtls = make(map[uint32]*secv1beta1.PeerAuthentication_MutualTLS)
		for port, mode := range pa_info.Pa_port_mtls {
			port_mtls[port] = &secv1beta1.PeerAuthentication_MutualTLS{Mode: mode}
		}
	}
	if pa_info.Pa_mtls_mode != secv1beta1.PeerAuthentication_MutualTLS_UNSET {
		mtls = &secv1beta1.PeerAuthentication_MutualTLS{
			Mode: pa_info.Pa_mtls_mode,
		}
	}

	pa_update.Spec = secv1beta1.PeerAuthentication{
		Selector:      selector,
		Mtls:          mtls,
		PortLevelMtls: port_mtls,
	}

	pa_update, err = obj_istio_cmd.client_set.SecurityV1beta1().PeerAuthentications(namespace).
		Create(context.TODO(), pa_update, metav1.CreateOptions{})
	if err != nil {
		util.LOG_ERR("Failed to create PeerAuthentications in %s namespace: %s, info: %v", namespace, err.Error(), pa_info)
		return false
	}

	util.LOG_DBG("create PeerAuthentications name: %+v", pa_update.ObjectMeta.Name)

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Get_pa(namespace string, pa_name string, pa_info *St_pa_info) bool {
	pa, err := obj_istio_cmd.client_set.SecurityV1beta1().PeerAuthentications(namespace).Get(context.TODO(),
		pa_info.Pa_name, metav1.GetOptions{})
	if err != nil {
		util.LOG_DBG("Failed to get PeerAuthentications in %s namespace, %s: %s", namespace, pa_info.Pa_name, err.Error())
		return false
	}

	*pa_info = St_pa_info{}

	pa_info.Pa_name = pa.ObjectMeta.Name
	pa_info.Pa_match_label = pa.Spec.Selector.MatchLabels
	if pa.Spec.Mtls != nil {
		pa_info.Pa_mtls_mode = pa.Spec.Mtls.Mode
	}

	pa_info.Pa_port_mtls = make(map[uint32]secv1beta1.PeerAuthentication_MutualTLS_Mode)
	for port, mode := range pa.Spec.PortLevelMtls {
		pa_info.Pa_port_mtls[port] = mode.Mode
	}

	return true
}

func (obj_istio_cmd *Obj_IstioCmd) Del_pa(namespace string, pa_name string) bool {
	err := obj_istio_cmd.client_set.SecurityV1beta1().PeerAuthentications(namespace).Delete(context.TODO(), pa_name, metav1.DeleteOptions{})
	if err != nil {
		util.LOG_ERR("Failed to delete PeerAuthentications in %s namespace, %s: %s", namespace, pa_name, err.Error())
		return false
	}

	util.LOG_DBG("delete PeerAuthentications name: %+v", pa_name)

	return true
}
