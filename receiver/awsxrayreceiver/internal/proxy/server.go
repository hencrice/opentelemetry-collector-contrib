// Package proxy provides an http server to act as a signing proxy for SDKs calling AWS X-Ray APIs
package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/aws/aws-xray-daemon/daemon/conn"
	"github.com/prometheus/common/log"
	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/config/configtls"
	"go.uber.org/zap"
)

// Config is the configuration for the local TCP proxy server.
type Config struct {
	// endpoint is the TCP address and port on which this receiver listens for
	// calls from the X-Ray SDK and relays them to the AWS X-Ray backend to
	// get sampling rules and report sampling statistics.
	confignet.TCPAddr `mapstructure:",squash"`

	// ProxyAddress defines the proxy address that the local TCP server
	// forwards HTTP requests to AWS X-Ray backend through.
	ProxyAddress string `mapstructure:"proxy_address"`

	// TLSSetting struct exposes TLS client configuration when forwarding
	// calls to the AWS X-Ray backend.
	TLSSetting configtls.TLSClientSetting `mapstructure:",squash"`

	// Region is the AWS region the local TCP server forwards requests to.
	Region string `mapstructure:"region"`

	// RoleARN is the IAM role used by the local TCP server when
	// communicating with the AWS X-Ray service.
	RoleARN string `mapstructure:"role_arn"`

	// AWSEndpoint is the X-Ray service endpoint which the local
	// TCP server forwards requests to.
	AWSEndpoint string `mapstructure:"aws_endpoint"`

	// LocalMode determines whether the EC2 instance metadata endpoint
	// will be called or not. Set to `true` to skip EC2 instance
	// metadata check.
	LocalMode *bool `mapstructure:"local_mode"`
}

type server struct {
	*http.Server
	log *zap.Logger
}

// const (
// 	service    = "xray"
// 	connHeader = "Connection"
// )

// Server represents HTTP server.
type Server interface {
	ListenAndServe() error
	Close() error
}

// NewServer returns a local TCP server that proxies requests to AWS
// backend using the given credentials.
func NewServer(cfg *Config, logger *zap.Logger) (*Server, error) {
	_, err := net.ResolveTCPAddr("tcp", cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	endPoint, er := getServiceEndpoint(awsCfg)

	if er != nil {
		return nil, fmt.Errorf("%v", er)
	}

	log.Infof("HTTP Proxy server using X-Ray Endpoint : %v", endPoint)

	// Parse url from endpoint
	url, err := url.Parse(endPoint)
	if err != nil {
		return nil, fmt.Errorf("unable to parse xray endpoint: %v", err)
	}

	signer := &v4.Signer{
		Credentials: sess.Config.Credentials,
	}

	transport := conn.ProxyServerTransport(cfg)

	// Reverse proxy handler
	handler := &httputil.ReverseProxy{
		Transport: transport,

		// Handler for modifying and forwarding requests
		Director: func(req *http.Request) {
			if req != nil && req.URL != nil {
				log.Debugf("Received request on HTTP Proxy server : %s", req.URL.String())
			} else {
				log.Debug("Request/Request.URL received on HTTP Proxy server is nil")
			}

			// Remove connection header before signing request, otherwise the
			// reverse-proxy will remove the header before forwarding to X-Ray
			// resulting in a signed header being missing from the request.
			req.Header.Del(connHeader)

			// Set req url to xray endpoint
			req.URL.Scheme = url.Scheme
			req.URL.Host = url.Host
			req.Host = url.Host

			// Consume body and convert to io.ReadSeeker for signer to consume
			body, err := consume(req.Body)
			if err != nil {
				log.Errorf("Unable to consume request body: %v", err)

				// Forward unsigned request
				return
			}

			// Sign request. signer.Sign() also repopulates the request body.
			_, err = signer.Sign(req, body, service, *awsCfg.Region, time.Now())
			if err != nil {
				log.Errorf("Unable to sign request: %v", err)
			}
		},
	}

	return &server{
		Server: &http.Server{
			Addr:    cfg.Socket.TCPAddress,
			Handler: handler,
		},
		log: logger,
	}, nil
}

// // consume readsAll() the body and creates a new io.ReadSeeker from the content. v4.Signer
// // requires an io.ReadSeeker to be able to sign requests. May return a nil io.ReadSeeker.
// func consume(body io.ReadCloser) (io.ReadSeeker, error) {
// 	var buf []byte

// 	// Return nil ReadSeeker if body is nil
// 	if body == nil {
// 		return nil, nil
// 	}

// 	// Consume body
// 	buf, err := ioutil.ReadAll(body)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return bytes.NewReader(buf), nil
// }

// // Serve starts server.
// func (s *Server) Serve() {
// 	log.Infof("Starting proxy http server on %s", s.Addr)
// 	s.ListenAndServe()
// }

// // Close stops server.
// func (s *Server) Close() {
// 	s.Server.Close()
// }

// // getServiceEndpoint returns X-Ray service endpoint.
// // It is guaranteed that awsCfg config instance is non-nil and the region value is non nil or non empty in awsCfg object.
// // Currently the caller takes care of it.
// func getServiceEndpoint(awsCfg *aws.Config) (string, error) {
// 	if awsCfg.Endpoint == nil || *awsCfg.Endpoint == "" {
// 		if awsCfg.Region == nil || *awsCfg.Region == "" {
// 			return "", errors.New("unable to generate endpoint from region with nil value")
// 		}
// 		resolved, err := endpoints.DefaultResolver().EndpointFor(service, *awsCfg.Region, setResolverConfig())
// 		return resolved.URL, err
// 	}
// 	return *awsCfg.Endpoint, nil
// }

// func setResolverConfig() func(*endpoints.Options) {
// 	return func(p *endpoints.Options) {
// 		p.ResolveUnknownService = true
// 	}
// }
