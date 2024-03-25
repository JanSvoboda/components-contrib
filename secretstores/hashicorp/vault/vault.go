/*
Copyright 2021 The Dapr Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/crypto/pkcs12"

	jsoniter "github.com/json-iterator/go"
	"golang.org/x/net/http2"

	"github.com/dapr/components-contrib/metadata"
	"github.com/dapr/components-contrib/secretstores"
	"github.com/dapr/kit/logger"
	kitmd "github.com/dapr/kit/metadata"
)

const (
	defaultVaultAddress          string         = "https://127.0.0.1:8200"
	defaultVaultEnginePath       string         = "secret"
	defaultVaultAuthMethod       authMethodType = "token"
	componentVaultAddress        string         = "vaultAddr"
	componentCaCert              string         = "caCert"
	componentCaPath              string         = "caPath"
	componentCaPem               string         = "caPem"
	componentSkipVerify          string         = "skipVerify"
	componentTLSServerName       string         = "tlsServerName"
	componentVaultToken          string         = "vaultToken"
	componentVaultTokenMountPath string         = "vaultTokenMountPath"
	componentVaultKVPrefix       string         = "vaultKVPrefix"
	componentVaultKVUsePrefix    string         = "vaultKVUsePrefix"
	defaultVaultKVPrefix         string         = "dapr"
	vaultHTTPHeader              string         = "X-Vault-Token"
	vaultHTTPRequestHeader       string         = "X-Vault-Request"
	vaultEnginePath              string         = "enginePath"
	vaultValueType               string         = "vaultValueType"
	versionID                    string         = "version_id"

	DataStr        string = "data"
	AuthStr        string = "auth"
	ClientTokenStr string = "client_token"
)

type valueType string

const (
	valueTypeMap  valueType = "map"
	valueTypeText valueType = "text"
)

type authMethodType string

const (
	token    authMethodType = "token"
	cert     authMethodType = "cert"
	approle  authMethodType = "approle"
	userpass authMethodType = "userpass"
)

var _ secretstores.SecretStore = (*vaultSecretStore)(nil)

func (v valueType) isMapType() bool {
	return v == valueTypeMap
}

var ErrNotFound = errors.New("secret key or version not exist")

// vaultSecretStore is a secret store implementation for HashiCorp Vault.
type vaultSecretStore struct {
	client              *http.Client
	vaultAddress        string
	vaultAuthMethod     authMethodType
	vaultNamespace      string
	vaultToken          string
	vaultTokenMountPath string
	vaultKVPrefix       string
	vaultEnginePath     string
	vaultValueType      valueType
	vaultLoginId        string
	vaultLoginSecret    string

	json jsoniter.API

	logger logger.Logger
}

type VaultMetadata struct {
	AuthMethod          string
	CaCert              string
	CaPath              string
	CaPem               string
	SkipVerify          string
	TLSServerName       string
	VaultAddr           string
	VaultKVPrefix       string
	VaultKVUsePrefix    bool
	VaultToken          string
	VaultTokenMountPath string
	EnginePath          string
	VaultValueType      string
	VaultNamespace      string
	ClientKeyStorePath  string
	ClientKeyStorePass  string
	LoginId             string
	LoginSecret         string
}

// tlsConfig is TLS configuration to interact with HashiCorp Vault.
type tlsConfig struct {
	vaultCAPem              string
	vaultCACert             string
	vaultCAPath             string
	vaultSkipVerify         bool
	vaultServerName         string
	vaultClientKeyStorePath string
	vaultClientKeyStorePass string
}

// vaultKVResponse is the response data from Vault KV.
type vaultKVResponse struct {
	Data struct {
		Data map[string]string `json:"data"`
	} `json:"data"`
}

// vaultListKVResponse is the response data from Vault KV.
type vaultListKVResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

type vaultLoginResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
}

// NewHashiCorpVaultSecretStore returns a new HashiCorp Vault secret store.
func NewHashiCorpVaultSecretStore(logger logger.Logger) secretstores.SecretStore {
	return &vaultSecretStore{
		client: &http.Client{},
		logger: logger,
		json:   jsoniter.ConfigFastest,
	}
}

// Init creates a HashiCorp Vault client.
func (v *vaultSecretStore) Init(ctx context.Context, meta secretstores.Metadata) error {
	m := VaultMetadata{
		VaultKVUsePrefix: true,
	}
	err := kitmd.DecodeMetadata(meta.Properties, &m)
	if err != nil {
		return err
	}

	// Get Vault address
	address := m.VaultAddr
	if address == "" {
		address = defaultVaultAddress
	}

	v.vaultAddress = address

	v.vaultEnginePath = defaultVaultEnginePath
	if m.EnginePath != "" {
		v.vaultEnginePath = m.EnginePath
	}

	v.vaultValueType = valueTypeMap
	if m.VaultValueType != "" {
		switch valueType(m.VaultValueType) {
		case valueTypeMap:
		case valueTypeText:
			v.vaultValueType = valueTypeText
		default:
			return fmt.Errorf("vault init error, invalid value type %s, accepted values are map or text", m.VaultValueType)
		}
	}

	// Generate TLS config
	tlsConf := metadataToTLSConfig(&m)

	// initialize http client with TLS config so that it can be used to fetch vault token if auth method is cert
	client, err := v.createHTTPClient(tlsConf)
	if err != nil {
		return fmt.Errorf("couldn't create client using config: %w", err)
	}

	v.client = client

	err = v.resolveAuthMethod(&m)
	if err != nil {
		return err
	}

	v.vaultNamespace = m.VaultNamespace

	switch v.vaultAuthMethod {
	case token:
		v.vaultToken = m.VaultToken
		v.vaultTokenMountPath = m.VaultTokenMountPath
		initErr := v.initVaultToken()
		if initErr != nil {
			return initErr
		}
	case approle, userpass:
		v.vaultLoginId = m.LoginId
		v.vaultLoginSecret = m.LoginSecret
		fallthrough
	case cert:
		initErr := v.vaultLogin(ctx)
		if initErr != nil {
			return initErr
		}
	}

	vaultKVPrefix := m.VaultKVPrefix
	if !m.VaultKVUsePrefix {
		vaultKVPrefix = ""
	} else if vaultKVPrefix == "" {
		vaultKVPrefix = defaultVaultKVPrefix
	}
	v.vaultKVPrefix = vaultKVPrefix

	return nil
}

func metadataToTLSConfig(meta *VaultMetadata) *tlsConfig {
	tlsConf := tlsConfig{}

	// Configure TLS settings
	skipVerify := meta.SkipVerify
	tlsConf.vaultSkipVerify = false
	if skipVerify == "true" {
		tlsConf.vaultSkipVerify = true
	}

	tlsConf.vaultCACert = meta.CaCert
	tlsConf.vaultCAPem = meta.CaPem
	tlsConf.vaultCAPath = meta.CaPath
	tlsConf.vaultServerName = meta.TLSServerName
	tlsConf.vaultClientKeyStorePath = meta.ClientKeyStorePath
	tlsConf.vaultClientKeyStorePass = meta.ClientKeyStorePass

	return &tlsConf
}

// GetSecret retrieves a secret using a key and returns a map of decrypted string/string values.
func (v *vaultSecretStore) getSecret(ctx context.Context, secret, version string) (*vaultKVResponse, error) {
	// Create get secret url
	var vaultSecretPathAddr string
	if v.vaultKVPrefix == "" {
		vaultSecretPathAddr = v.vaultAddress + "/v1/" + v.vaultEnginePath + "/data/" + secret + "?version=" + version
	} else {
		vaultSecretPathAddr = v.vaultAddress + "/v1/" + v.vaultEnginePath + "/data/" + v.vaultKVPrefix + "/" + secret + "?version=" + version
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, vaultSecretPathAddr, nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate request: %w", err)
	}
	// Set vault token.
	httpReq.Header.Set(vaultHTTPHeader, v.vaultToken)
	// Set X-Vault-Request header
	httpReq.Header.Set(vaultHTTPRequestHeader, "true")

	httpresp, err := v.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("couldn't get secret: %w", err)
	}

	defer httpresp.Body.Close()

	if httpresp.StatusCode != http.StatusOK {
		var b bytes.Buffer
		io.Copy(&b, httpresp.Body)
		v.logger.Debugf("getSecret %s couldn't get successful response: %#v, %s", secret, httpresp, b.String())
		if httpresp.StatusCode == http.StatusNotFound {
			// handle not found error
			return nil, fmt.Errorf("getSecret %s failed %w", secret, ErrNotFound)
		}

		return nil, fmt.Errorf("couldn't get successful response, status code %d, body %s",
			httpresp.StatusCode, b.String())
	}

	var d vaultKVResponse

	if v.vaultValueType.isMapType() {
		// parse the secret value to map[string]string
		if err := json.NewDecoder(httpresp.Body).Decode(&d); err != nil {
			return nil, fmt.Errorf("couldn't decode response body: %s", err)
		}
	} else {
		// treat the secret as string
		b, err := io.ReadAll(httpresp.Body)
		if err != nil {
			return nil, fmt.Errorf("couldn't read response: %s", err)
		}
		res := v.json.Get(b, DataStr, DataStr).ToString()
		d.Data.Data = map[string]string{
			secret: res,
		}
	}

	return &d, nil
}

// GetSecret retrieves a secret using a key and returns a map of decrypted string/string values.
func (v *vaultSecretStore) GetSecret(ctx context.Context, req secretstores.GetSecretRequest) (secretstores.GetSecretResponse, error) {
	// version 0 represent for latest version
	version := "0"
	if value, ok := req.Metadata[versionID]; ok {
		version = value
	}
	d, err := v.getSecret(ctx, req.Name, version)
	if err != nil {
		return secretstores.GetSecretResponse{Data: nil}, err
	}

	resp := secretstores.GetSecretResponse{
		Data: d.Data.Data,
	}

	return resp, nil
}

// BulkGetSecret retrieves all secrets in the store and returns a map of decrypted string/string values.
func (v *vaultSecretStore) BulkGetSecret(ctx context.Context, req secretstores.BulkGetSecretRequest) (secretstores.BulkGetSecretResponse, error) {
	version := "0"
	if value, ok := req.Metadata[versionID]; ok {
		version = value
	}

	resp := secretstores.BulkGetSecretResponse{
		Data: map[string]map[string]string{},
	}

	keys, err := v.listKeysUnderPath(ctx, "")
	if err != nil {
		return secretstores.BulkGetSecretResponse{}, err
	}

	for _, key := range keys {
		keyValues := map[string]string{}
		secrets, err := v.getSecret(ctx, key, version)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				// version not exist skip
				continue
			}

			return secretstores.BulkGetSecretResponse{Data: nil}, err
		}

		for k, v := range secrets.Data.Data {
			keyValues[k] = v
		}
		resp.Data[key] = keyValues
	}

	return resp, nil
}

// listKeysUnderPath get all the keys recursively under a given path.(returned keys including path as prefix)
// path should not has `/` prefix.
func (v *vaultSecretStore) listKeysUnderPath(ctx context.Context, path string) ([]string, error) {
	var vaultSecretsPathAddr string

	// Create list secrets url
	if v.vaultKVPrefix == "" {
		vaultSecretsPathAddr = fmt.Sprintf("%s/v1/%s/metadata/%s", v.vaultAddress, v.vaultEnginePath, path)
	} else {
		vaultSecretsPathAddr = fmt.Sprintf("%s/v1/%s/metadata/%s/%s", v.vaultAddress, v.vaultEnginePath, v.vaultKVPrefix, path)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "LIST", vaultSecretsPathAddr, nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate request: %s", err)
	}
	// Set vault token.
	httpReq.Header.Set(vaultHTTPHeader, v.vaultToken)
	// Set X-Vault-Request header
	httpReq.Header.Set(vaultHTTPRequestHeader, "true")
	httpresp, err := v.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("couldn't get secret: %s", err)
	}

	defer httpresp.Body.Close()

	if httpresp.StatusCode != http.StatusOK {
		var b bytes.Buffer
		io.Copy(&b, httpresp.Body)
		v.logger.Debugf("list keys couldn't get successful response: %#v, %s", httpresp, b.String())

		return nil, fmt.Errorf("list keys couldn't get successful response, status code: %d, status: %s, response %s",
			httpresp.StatusCode, httpresp.Status, b.String())
	}

	var d vaultListKVResponse

	if err := json.NewDecoder(httpresp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("couldn't decode response body: %s", err)
	}
	res := make([]string, 0, len(d.Data.Keys))
	for _, key := range d.Data.Keys {
		if v.isSecretPath(key) {
			res = append(res, path+key)
		} else {
			subKeys, err := v.listKeysUnderPath(ctx, path+key)
			if err != nil {
				return nil, err
			}
			res = append(res, subKeys...)
		}
	}

	return res, nil
}

// isSecretPath checks if the key is a valid secret path or it is part of the secret path.
func (v *vaultSecretStore) isSecretPath(key string) bool {
	return !strings.HasSuffix(key, "/")
}

func (v *vaultSecretStore) resolveAuthMethod(m *VaultMetadata) error {
	switch authMethodType(m.AuthMethod) {
	case token, cert, approle, userpass:
		v.vaultAuthMethod = authMethodType(m.AuthMethod)
	case "":
		v.vaultAuthMethod = token
	default:
		return fmt.Errorf("unsupported auth method: %s", m.AuthMethod)
	}
	return nil
}

// initVaultToken reads the vault token from the file if token is defined by mount path.
func (v *vaultSecretStore) initVaultToken() error {
	// Test that at least one of them are set if not return error
	if v.vaultToken == "" && v.vaultTokenMountPath == "" {
		return fmt.Errorf("token mount path and token not set")
	}

	// Test that both are not set. If so return error
	if v.vaultToken != "" && v.vaultTokenMountPath != "" {
		return fmt.Errorf("token mount path and token both set")
	}

	if v.vaultToken != "" {
		return nil
	}

	data, err := os.ReadFile(v.vaultTokenMountPath)
	if err != nil {
		return fmt.Errorf("couldn't read vault token from mount path %s err: %s", v.vaultTokenMountPath, err)
	}
	v.vaultToken = string(bytes.TrimSpace(data))

	return nil
}

func (v *vaultSecretStore) vaultLoginPayload() map[string]string {
	if v.vaultAuthMethod == userpass {
		return map[string]string{
			"password": v.vaultLoginSecret,
		}
	}

	if v.vaultAuthMethod == approle {
		return map[string]string{
			"role_id":   v.vaultLoginId,
			"secret_id": v.vaultLoginSecret,
		}
	}

	return map[string]string{}
}

func (v *vaultSecretStore) vaultLogin(ctx context.Context) error {
	if v.vaultAuthMethod == cert && v.client.Transport.(*http.Transport).TLSClientConfig.Certificates == nil {
		return fmt.Errorf("vault authentication method is %s but certificates are not set", string(v.vaultAuthMethod))
	}

	var vaultLoginPath string
	if v.vaultAuthMethod == userpass {
		vaultLoginPath = v.vaultAddress + "/v1" + "/auth/" + string(v.vaultAuthMethod) + "/login/" + v.vaultLoginId
	} else {
		vaultLoginPath = v.vaultAddress + "/v1" + "/auth/" + string(v.vaultAuthMethod) + "/login"
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, vaultLoginPath, nil)
	if err != nil {
		return fmt.Errorf("couldn't generate request: %s", err)
	}

	if v.vaultNamespace != "" {
		httpReq.Header.Set("X-Vault-Namespace", v.vaultNamespace)
	}

	postBody, err := json.Marshal(v.vaultLoginPayload())
	if err != nil {
		return fmt.Errorf("couldn't marshal request body: %s", err)
	}

	httpReq.Body = io.NopCloser(bytes.NewReader(postBody))

	httpresp, err := v.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("couldn't get secret: %s", err)
	}

	defer httpresp.Body.Close()

	if httpresp.StatusCode != http.StatusOK {
		var b bytes.Buffer
		io.Copy(&b, httpresp.Body)

		return fmt.Errorf("login couldn't get successful response, status code: %d, status: %s, response %s",
			httpresp.StatusCode, httpresp.Status, b.String())
	}

	var d vaultLoginResponse

	if err := json.NewDecoder(httpresp.Body).Decode(&d); err != nil {
		return fmt.Errorf("couldn't decode response body: %s", err)
	}

	if d.Auth.ClientToken == "" {
		return fmt.Errorf("couldn't get client token")
	}

	v.vaultToken = d.Auth.ClientToken

	return nil
}

func (v *vaultSecretStore) createHTTPClient(config *tlsConfig) (*http.Client, error) {
	tlsClientConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if config.vaultClientKeyStorePath != "" && config.vaultClientKeyStorePass != "" {
		if cert, err := getClientKeyPair(config.vaultClientKeyStorePath, config.vaultClientKeyStorePass); err != nil {
			return nil, err
		} else {
			tlsClientConfig.Certificates = append(tlsClientConfig.Certificates, *cert)
		}
	}

	if config != nil && config.vaultSkipVerify {
		v.logger.Infof("hashicorp vault: you are using 'skipVerify' to skip server config verify which is unsafe!")
	}

	tlsClientConfig.InsecureSkipVerify = config.vaultSkipVerify
	if !config.vaultSkipVerify {
		rootCAPools, err := v.getRootCAsPools(config.vaultCAPem, config.vaultCAPath, config.vaultCACert)
		if err != nil {
			return nil, err
		}

		tlsClientConfig.RootCAs = rootCAPools

		if config.vaultServerName != "" {
			tlsClientConfig.ServerName = config.vaultServerName
		}
	}

	// Setup http transport
	transport := &http.Transport{
		TLSClientConfig: tlsClientConfig,
	}

	// Configure http2 client
	err := http2.ConfigureTransport(transport)
	if err != nil {
		return nil, errors.New("failed to configure http2")
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

// getRootCAsPools returns root CAs when you give it CA Pem file, CA path, and CA Certificate. Default is system certificates.
func (v *vaultSecretStore) getRootCAsPools(vaultCAPem string, vaultCAPath string, vaultCACert string) (*x509.CertPool, error) {
	if vaultCAPem != "" {
		certPool := x509.NewCertPool()
		cert := []byte(vaultCAPem)
		if ok := certPool.AppendCertsFromPEM(cert); !ok {
			return nil, fmt.Errorf("couldn't read PEM")
		}

		return certPool, nil
	}

	if vaultCAPath != "" {
		certPool := x509.NewCertPool()
		if err := readCertificateFolder(certPool, vaultCAPath); err != nil {
			return nil, err
		}

		return certPool, nil
	}

	if vaultCACert != "" {
		certPool := x509.NewCertPool()
		if err := readCertificateFile(certPool, vaultCACert); err != nil {
			return nil, err
		}

		return certPool, nil
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("couldn't read system certs: %s", err)
	}

	return certPool, nil
}

// func getClientKeyPair(vaultClientCert string, vaultClientKey string, vaultClientCertPath string, vaultClientKeyPath string, vaultClientKeyStorePath string, vaultClientKeyStorePass string) (*tls.Certificate, error) {
func getClientKeyPair(vaultClientKeyStorePath string, vaultClientKeyStorePass string) (*tls.Certificate, error) {
	// load pkcs12 keystore and return it as *tls.Certificate
	p12_data, err := os.ReadFile(vaultClientKeyStorePath)

	if err != nil {
		return nil, err
	}

	key, cert, err := pkcs12.Decode(p12_data, vaultClientKeyStorePass)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}, nil

	// if vaultClientCert != "" && vaultClientKey != "" {
	// 	cert, err := tls.X509KeyPair([]byte(vaultClientCert), []byte(vaultClientKey))
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	return &cert, nil
	// }

	// if vaultClientCertPath != "" && vaultClientKeyPath != "" {
	// 	cert, err := tls.LoadX509KeyPair(vaultClientCertPath, vaultClientKeyPath)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	return &cert, nil
	// }

	// return nil, nil
}

// readCertificateFile reads the certificate at given path.
func readCertificateFile(certPool *x509.CertPool, path string) error {
	// Read certificate file
	pemFile, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("couldn't read CA file from disk: %s", err)
	}

	if ok := certPool.AppendCertsFromPEM(pemFile); !ok {
		return fmt.Errorf("couldn't read PEM")
	}

	return nil
}

// readCertificateFolder scans a folder for certificates.
func readCertificateFolder(certPool *x509.CertPool, path string) error {
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		return readCertificateFile(certPool, p)
	})
	if err != nil {
		return fmt.Errorf("couldn't read certificates at %s: %s", path, err)
	}

	return nil
}

// Features returns the features available in this secret store.
func (v *vaultSecretStore) Features() []secretstores.Feature {
	if v.vaultValueType == valueTypeText {
		return []secretstores.Feature{}
	}

	return []secretstores.Feature{secretstores.FeatureMultipleKeyValuesPerSecret}
}

func (v *vaultSecretStore) GetComponentMetadata() (metadataInfo metadata.MetadataMap) {
	metadataStruct := VaultMetadata{}
	metadata.GetMetadataInfoFromStructType(reflect.TypeOf(metadataStruct), &metadataInfo, metadata.SecretStoreType)
	return
}
