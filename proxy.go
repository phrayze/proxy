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
	"time"

	dataproc "cloud.google.com/go/dataproc/apiv1"
	"cloud.google.com/go/dataproc/apiv1/dataprocpb"
	"golang.org/x/net/http2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

var allowedMethods = []string{http.MethodGet, http.MethodHead}
var allowedPathPrefixes = []string{"/"}
var reusableTokenSource oauth2.TokenSource

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
	for _, allowed := range allowedMethods {
		if method == allowed {
			return true
		}
	}
	return false
}

func pathAllowed(path string) bool {
	for _, allowedPrefix := range allowedPathPrefixes {
		if strings.HasPrefix(path, allowedPrefix) {
			return true
		}
	}
	return false
}

func clusterURL(ctx context.Context, project, region, clusterName string) (*url.URL, error) {
	endpoint := region + "-dataproc.googleapis.com:443"
	// Create a new Dataproc client.
	client, err := dataproc.NewClusterControllerClient(ctx, option.WithEndpoint(endpoint))
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
	targetProject := os.Getenv("PROJECT")
	targetRegion := os.Getenv("REGION")
	targetCluster := os.Getenv("CLUSTER")

	return clusterURL(r.Context(), targetProject, targetRegion, targetCluster)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if !methodAllowed(r.Method) || !pathAllowed(r.URL.Path) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	backendURL, err := targetBackendURL(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create a new reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	// Customize the director function to modify the request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = backendURL.Host
		req.URL.Path = r.URL.Path
		req.URL.RawPath = r.URL.Path
		req.URL.Scheme = backendURL.Scheme
		req.URL.Host = backendURL.Host

		// Get and set the authentication token
		token, err := reusableTokenSource.Token()
		if err != nil {
			log.Printf("Error getting token: %v", err)
			return
		}
		token.SetAuthHeader(req)
		log.Printf("[%q] proxied request for %+v: %+v", backendURL, r.URL.Path, req)
	}

	// Create a custom transport with explicit settings
	transport := &http.Transport{
		// Ensure we maintain the host header
		ForceAttemptHTTP2: true,
		// Configure proper TLS settings
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Only for development
		},
		// Set proper timeouts and connection settings
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Assign our custom transport to the proxy
	proxy.Transport = transport
	// Set up custom transport for HTTP/2 if needed
	if backendURL.Scheme == "http" {
		proxy.Transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network string, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		}
	}

	proxy.ServeHTTP(w, r)
}

func main() {
	flag.Parse()
	reusableTokenSource = oauth2.ReuseTokenSource(nil, defaultTokenSource(context.Background()))
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
