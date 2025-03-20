// authproxy proxies HTTP requests to a backend while adding auth information to every request.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	dataproc "cloud.google.com/go/dataproc/apiv1"
	"cloud.google.com/go/dataproc/apiv1/dataprocpb"

	"golang.org/x/net/http2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option" // Import insecure credentials
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	backend             = flag.String("backend", "", "url of the backend HTTP server")
	allowedMethods      = flag.String("allowed-methods", "http.MethodGet, http.MethodHead", "Set of allowed HTTP methods")
	allowedPathPrefixes = flag.String("allowed-path-prefixes", "/", "Set of allowed HTTP request URL paths")
	endpoint            = "" // will be defined later
)
// configHelperResp corresponds to the JSON output of the `gcloud config-helper` command.
type configHelperResp struct {
	Credential struct {
		AccessToken string `json:"access_token"`
		TokenExpiry string `json:"token_expiry"`
	} `json:"credential"`
}

func gcloudToken() (*oauth2.Token, error) {
	credentials, err := google.FindDefaultCredentials(context.Background())
	if err != nil {
		log.Fatalf("failed to get default credentials: %v", err)
	}
	tokenSource := credentials.TokenSource
	if tokenSource == nil {
		return nil, fmt.Errorf("failed to create NewTokenSource: %v", err)
	}

	// Access the token
	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}
	return token, nil
}

type tokenSourceFunc func() (*oauth2.Token, error)

func (tsf tokenSourceFunc) Token() (*oauth2.Token, error) {
	return tsf()
}

func defaultTokenSource(ctx context.Context) oauth2.TokenSource {
	dts, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return dts
	}
	return tokenSourceFunc(gcloudToken)
}

func methodAllowed(method string) bool {
	allowed := strings.Split(*allowedMethods, ",")
	for _, allowedMethod := range allowed {
		if method == allowedMethod {
			return true
		}
	}
	return false
}

func pathAllowed(path string) bool {
	prefixes := strings.Split(*allowedPathPrefixes, ",")
	for _, allowedPrefix := range prefixes {
		if strings.HasPrefix(path, allowedPrefix) {
			return true
		}
	}
	return false
}

// NewClusterControllerClient creates a new cluster controller client.
func NewClusterControllerClient(ctx context.Context, opts ...option.ClientOption) (*dataproc.ClusterControllerClient, error) {
	conn, err := grpc.Dial(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock()) // Corrected line
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %v", err)
	}
	clusterControllerClient, err := dataproc.NewClusterControllerClient(ctx, option.WithGRPCConn(conn))
	if err != nil {
		return nil, err
	}
	return clusterControllerClient, nil
}

func clusterURL(ctx context.Context, project, region, clusterName string) (*url.URL, error) {
	endpoint := region + "-dataproc.googleapis.com:443"
	// Create a new Dataproc client.
	//define endpoint here as the region is known
	client, err := NewClusterControllerClient(ctx, option.WithEndpoint(endpoint))
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	// Build the GetCluster request.
	req := &dataprocpb.GetClusterRequest{
		ProjectId:   project,
		Region:      region,
		ClusterName: clusterName,
	}

	// Call the GetCluster method.
	cluster, err := client.GetCluster(ctx, req)
	if err != nil {
		log.Fatalf("failed to get cluster: %v", err)
	}

	/*
	// Check if InternalIpOnly is empty before using it
	if cluster.Config == nil || cluster.Config.GceClusterConfig == nil {
		return nil, fmt.Errorf("cluster %s has no GceClusterConfig", clusterName)
	}

	if !cluster.Config.GceClusterConfig.GetInternalIpOnly() {
		return nil, fmt.Errorf("cluster %s is not configured for internal IP only", clusterName)
	}
	*/

	for _, endpoint := range cluster.Config.EndpointConfig.HttpPorts {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, err
		}
		u.Path = "/"
		return u, nil
	}
	return nil, fmt.Errorf("no HTTP endpoints defined for the cluster %q", clusterName)
}

func targetBackendURL(r *http.Request) (*url.URL, error) {
	if len(*backend) > 0 {
		return url.Parse(*backend)
	}

	targetProject := os.Getenv("PROJECT")
	targetRegion := os.Getenv("REGION")
	targetCluster := os.Getenv("CLUSTER")
	log.Printf("GCP Project: " + targetProject)
	log.Printf("GCP Region: " + targetRegion)
	log.Printf("GCP DataProc Cluster: " + targetCluster)

	if len(targetCluster) > 0 {
		return clusterURL(r.Context(), targetProject, targetRegion, targetCluster)
	}
	hostParts := strings.Split(r.Host, "-dot-")
	if len(hostParts) < 2 {
		return nil, fmt.Errorf("unable to identify cluster name from hostname")
	}
	return clusterURL(r.Context(), targetProject, targetRegion, hostParts[0])
}

func proxy() http.Handler {
	tokenSource := oauth2.ReuseTokenSource(nil, defaultTokenSource(context.Background()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !methodAllowed(r.Method) || !pathAllowed(r.URL.Path) {
			log.PrintF("Method %+v is not allowed", r.method)
			log.PrintF("Path %+v is not allowed", r.URL.Path)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		
		backendURL, err := targetBackendURL(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("backendURL: %+v", backendURL)
		log.Printf("r.URL.Path: %+v", r.URL.Path)

		proxy := httputil.NewSingleHostReverseProxy(backendURL)
		if backendURL.Scheme == "http" {
			proxy.Transport = &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network string, addr string, cfg *tls.Config) (net.Conn, error) {
					return net.Dial(network, addr)
				},
			}
		}
		log.Printf("[%q] proxied request for %+v: %+v", backendURL, r.URL.Path, r)
		token, err := tokenSource.Token()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		token.SetAuthHeader(r)
		r.Host = backendURL.Host
		r.URL.Scheme = backendURL.Scheme
		proxy.ServeHTTP(w, r)
	})
}

func main() {
	flag.Parse()
	handler := proxy()
	log.Printf("Starting proxy on port 8080")
	err := http.ListenAndServe(":8080", handler)
	if err != nil {
		panic(err)
	}
}
