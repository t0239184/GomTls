package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello, world!\n")
	})
	// Run_HTTP()
	// Run_HTTPS()
	Run_HTTPS_mTLS()
	// Run_HTTPS_mTLS_with_wrong_certificate()
}

func Run_HTTP() {
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func Run_HTTPS() {
	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(http.ListenAndServeTLS(
		":443",
		"certificates/mock.ds.server.chain.pem",
		"certificates/mock.ds.server.key",
		nil))
}

func Run_HTTPS_mTLS() {
	// Load CA certificate from file or database
	caCert, err := ioutil.ReadFile("./certificates/intermediate.ca.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Create CA certificate pool
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}
	log.Fatal(server.ListenAndServeTLS(
		"certificates/mock.ds.server.chain.pem",
		"certificates/mock.ds.server.key"))
}

func Run_HTTPS_mTLS_with_wrong_certificate() {
	// Load CA certificate from file or database
	caCert, err := ioutil.ReadFile("./certificates/intermediate.ca.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Create CA certificate pool
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}
	log.Fatal(server.ListenAndServeTLS(
		"certificates/wrong.mock.ds.server.chain.pem",
		"certificates/mock.ds.server.key"))
}
