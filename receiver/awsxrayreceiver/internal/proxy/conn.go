// Copyright 2018-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package conn

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"go.uber.org/zap"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	log "github.com/cihub/seelog"
	"golang.org/x/net/http2"
)

const (
	// these are not configurable by customers in the X-Ray daemon
	// so keep them hardcoded:
	// https://github.com/aws/aws-xray-daemon/blob/master/pkg/cfg/cfg.go#L195
	requestTimeout = 2 * time.Second
	// https://github.com/aws/aws-xray-daemon/blob/master/pkg/cfg/cfg.go#L118
	idleConnTimeout = 30 * time.Second
	// https://github.com/aws/aws-xray-daemon/blob/master/pkg/cfg/cfg.go#L119
	maxIdleConnsPerHost = 2

	awsRegionEnvVar                   = "AWS_REGION"
	ecsContainerMetadataEnabledEnvVar = "ECS_ENABLE_CONTAINER_METADATA"
	ecsMetadataFileEnvVar             = "ECS_CONTAINER_METADATA_FILE"

	httpsProxyEnvVar = "HTTPS_PROXY"
)

var newAWSSession = func(roleArn string, region string) (*session.Session, error) {
	var s *session.Session
	var err error
	if roleArn == "" {
		s = getDefaultSession()
	} else {
		stsCreds := getSTSCreds(region, roleArn)

		s, err = session.NewSession(&aws.Config{
			Credentials: stsCreds,
		})

		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

var getEC2Region = func(s *session.Session) (string, error) {
	return ec2metadata.New(s).Region()
}

func getAWSConfigSession(c *Config, log *zap.Logger) (*aws.Config, *session.Session, error) {
	var awsRegion string
	http, err := getNewHTTPClient(c.TLSSetting.Insecure, c.ProxyAddress)
	if err != nil {
		return nil, nil, err
	}
	regionEnv := os.Getenv(awsRegionEnvVar)
	if c.Region == "" && regionEnv != "" {
		awsRegion = regionEnv
		log.Debug("Fetch region from environment variables", zap.String("value", awsRegion))
	} else if c.Region != "" {
		awsRegion = c.Region
		log.Debug("Fetch region from config file", zap.String("value", awsRegion))
	} else if !c.LocalMode {
		awsRegion, err = getRegionFromECSMetadata()
		if err != nil {
			log.Debug("Unable to fetch region from ECS metadata", zap.Error(err))
			awsRegion, err = getEC2Region(getDefaultSession())
			if err != nil {
				log.Debug("Unable to fetch region from EC2 metadata", zap.Error(err))
			} else {
				log.Debugf("Fetch region from ec2 metadata", zap.String("value", awsRegion))
			}
		} else {
			log.Debug("Fetch region from ECS metadata file", zap.String("value", awsRegion))
		}

	}
	if awsRegion == "" {
		return nil, nil, errors.New("cannot fetch region variable from config file, environment variables, ecs metadata, or ec2 metadata.")
	}

	sess, err := newAWSSession(c.RoleARN, awsRegion)
	if err != nil {
		return nil, nil, err
	}

	return &aws.Config{
		Region:                 aws.String(awsRegion),
		DisableParamValidation: aws.Bool(true),
		MaxRetries:             aws.Int(2),
		Endpoint:               aws.String(c.AWSEndpoint),
		HTTPClient:             http,
	}, sess
}

func getNewHTTPClient(insecure bool, proxyAddress *string) (*http.Client, error) {
	tls := &tls.Config{
		InsecureSkipVerify: insecure,
	}

	finalProxyAddress := getProxyAddress(proxyAddress)
	proxyURL, err := getProxyURL(finalProxyAddress)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: tls,
		Proxy:           http.ProxyURL(proxyURL),
	}

	// is not enabled by default as we configure TLSClientConfig for supporting SSL to data plane.
	// http2.ConfigureTransport will setup transport layer to use HTTP2
	http2.ConfigureTransport(transport)
	http := &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}
	return http, nil
}

func getProxyAddress(proxyAddress string) string {
	var finalProxyAddress string
	if proxyAddress != "" {
		finalProxyAddress = proxyAddress
	} else if proxyAddress == "" && os.Getenv(httpsProxyEnvVar) != "" {
		finalProxyAddress = os.Getenv(httpsProxyEnvVar)
	} else {
		finalProxyAddress = ""
	}
	return finalProxyAddress
}

func getProxyURL(finalProxyAddress string) (*url.URL, error) {
	var proxyURL *url.URL
	var err error
	if finalProxyAddress != "" {
		proxyURL, err = url.Parse(finalProxyAddress)
		if err != nil {
			return nil, err
		}
	} else {
		proxyURL = nil
	}
	return proxyURL, nil
}

func getRegionFromECSMetadata() (string, error) {
	var region string

	ecsMetadataEnabled := os.Getenv(ecsContainerMetadataEnabledEnvVar)
	ecsMetadataEnabled = strings.ToLower(ecsMetadataEnabled)
	if ecsMetadataEnabled == "true" {
		metadataFilePath := os.Getenv(ecsMetadataFileEnvVar)
		metadataFile, err := ioutil.ReadFile(metadataFilePath)
		if err != nil {
			return "", fmt.Errorf("unable to open ECS metadata file, path: %s, error: %w",
				metadataFilePath, err)
		} else {
			var dat map[string]interface{}
			if err := json.Unmarshal(metadataFile, &dat); err != nil {
				return "", fmt.Errorf("unable to read ECS metadatafile contents, path: %s, error: %w",
					metadataFilePath, err)
			} else {
				taskArn := strings.Split(dat["TaskARN"].(string), ":")
				region = taskArn[3]
			}
		}
	}
	return region, nil
}

// proxyServerTransport configures HTTP transport for TCP Proxy Server.
func proxyServerTransport(config *Config) *http.Transport {
	tls := &tls.Config{
		InsecureSkipVerify: config.TLSSetting.Insecure,
	}

	proxyAddr := getProxyAddress(config.ProxyAddress)
	proxyURL := getProxyURL(proxyAddr)

	// Connection timeout in seconds
	idleConnTimeout := time.Duration(config.ProxyServer.IdleConnTimeout) * time.Second

	transport := &http.Transport{
		MaxIdleConnsPerHost: maxIdleConnsPerHost,
		IdleConnTimeout:     idleConnTimeout,
		Proxy:               http.ProxyURL(proxyURL),
		TLSClientConfig:     tls,

		// If not disabled the transport will add a gzip encoding header
		// to requests with no `accept-encoding` header value. The header
		// is added after we sign the request which invalidates the
		// signature.
		DisableCompression: true,
	}

	return transport
}

// TODO more to updates

// getSTSCreds gets STS credentials from regional endpoint. ErrCodeRegionDisabledException is received if the
// STS regional endpoint is disabled. In this case STS credentials are fetched from STS primary regional endpoint
// in the respective AWS partition.
func getSTSCreds(region string, roleArn string) *credentials.Credentials {
	t := getDefaultSession()

	stsCred := getSTSCredsFromRegionEndpoint(t, region, roleArn)
	// Make explicit call to fetch credentials.
	_, err := stsCred.Get()
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case sts.ErrCodeRegionDisabledException:
				log.Errorf("Region : %v - %v", region, aerr.Error())
				log.Info("Credentials for provided RoleARN will be fetched from STS primary region endpoint instead of regional endpoint.")
				stsCred = getSTSCredsFromPrimaryRegionEndpoint(t, roleArn, region)
			}
		}
	}
	return stsCred
}

// getSTSCredsFromRegionEndpoint fetches STS credentials for provided roleARN from regional endpoint.
// AWS STS recommends that you provide both the Region and endpoint when you make calls to a Regional endpoint.
// Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html#id_credentials_temp_enable-regions_writing_code
func getSTSCredsFromRegionEndpoint(sess *session.Session, region string, roleArn string) *credentials.Credentials {
	regionalEndpoint := getSTSRegionalEndpoint(region)
	// if regionalEndpoint is "", the STS endpoint is Global endpoint for classic regions except ap-east-1 - (HKG)
	// for other opt-in regions, region value will create STS regional endpoint.
	// This will be only in the case, if provided region is not present in aws_regions.go
	c := &aws.Config{Region: aws.String(region), Endpoint: &regionalEndpoint}
	st := sts.New(sess, c)
	log.Infof("STS Endpoint : %v", st.Endpoint)
	return stscreds.NewCredentialsWithClient(st, roleArn)
}

// getSTSCredsFromPrimaryRegionEndpoint fetches STS credentials for provided roleARN from primary region endpoint in the
// respective partition.
func getSTSCredsFromPrimaryRegionEndpoint(t *session.Session, roleArn string, region string) *credentials.Credentials {
	partitionId := getPartition(region)
	if partitionId == endpoints.AwsPartitionID {
		return getSTSCredsFromRegionEndpoint(t, endpoints.UsEast1RegionID, roleArn)
	} else if partitionId == endpoints.AwsCnPartitionID {
		return getSTSCredsFromRegionEndpoint(t, endpoints.CnNorth1RegionID, roleArn)
	} else if partitionId == endpoints.AwsUsGovPartitionID {
		return getSTSCredsFromRegionEndpoint(t, endpoints.UsGovWest1RegionID, roleArn)
	}

	return nil
}

func getSTSRegionalEndpoint(r string) string {
	p := getPartition(r)

	var e string
	if p == endpoints.AwsPartitionID || p == endpoints.AwsUsGovPartitionID {
		e = STSEndpointPrefix + r + STSEndpointSuffix
	} else if p == endpoints.AwsCnPartitionID {
		e = STSEndpointPrefix + r + STSAwsCnPartitionIDSuffix
	}
	return e
}

func getDefaultSession() *session.Session {
	result, serr := session.NewSession()
	if serr != nil {
		log.Errorf("Error in creating session object : %v\n.", serr)
		os.Exit(1)
	}
	return result
}

// getPartition return AWS Partition for the provided region.
func getPartition(region string) string {
	p, _ := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), region)
	return p.ID()
}
