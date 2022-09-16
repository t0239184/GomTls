# mTLS implement with Golang
#mTLS #2WayTLS 

---
## Code

```
.
├── .gitignore
├── LICENSE
├── README.md
├── certificates
│   ├── client.server.chain.pem
│   ├── client.server.pem
│   ├── intermediate.ca.csr
│   ├── intermediate.ca.key
│   ├── intermediate.ca.pem
│   ├── intermediate.srl
│   ├── mock.ds.server.chain.pem
│   ├── mock.ds.server.chain.pem.sha1
│   ├── mock.ds.server.csr
│   ├── mock.ds.server.key
│   ├── mock.ds.server.pem
│   ├── mock.ds.server.pem.sha1
│   ├── root.ca.key
│   ├── root.ca.pem
│   ├── root.srl
│   ├── wrong.client.server.chain.pem
│   ├── wrong.client.server.pem
│   ├── wrong.mock.ds.server.chain.pem
│   ├── wrong.mock.ds.server.csr
│   └── wrong.mock.ds.server.pem
├── client.note
├── client_certificates
│   ├── client.server.chain.pem
│   ├── client.server.csr
│   ├── client.server.key
│   ├── client.server.pem
│   ├── intermediate.ca.pem
│   ├── wrong.client.server.chain.pem
│   ├── wrong.client.server.pem
│   └── wrong_client.server.csr
├── go.mod
└── server.go

2 directories, 34 files

```
---

server.go
```go
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
	http.HandleFunc("/hello", func (w http.ResponseWriter, r *http.Request) {
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
```

---

## Setup TLS Part

### Generate Root CA Certificate
```sh
openssl genrsa -out root.ca.key 2048
openssl req -new -x509 -days 365 \
        -subj "/C=TW/ST=Taipei/O=RootCA/OU=IT/CN=www.rootca.com"
        -key root.ca.key \
        -out root.ca.crt
```

---
### Generate Intermediate CA Certificate
```sh
openssl genrsa -out intermediate.ca.key 2048
openssl req -new -sha256 -key intermediate.ca.key \
        -subj "/C=TW/ST=Taipei/O=ImIntermediateca/OU=IT/CN=www.intermediate.com" \
        -out intermediate.ca.csr
openssl x509 -req -CAcreateserial -days 365 \
        -CA root.ca.crt \
        -CAkey root.ca.key \
        -in intermediate.ca.csr \
        -out intermediate.ca.pem
```

---
### Generate Server Certificate
```sh
openssl genrsa -out mock.ds.server.key 2048
openssl req -new -sha256 -key mock.ds.server.key \
        -subj "/C=TW/ST=Taipei/O=ImMockDS/OU=IT/CN=127.0.0.1" \
        -out mock.ds.server.csr
openssl x509 -req -CAcreateserial -days 365 \
        -CA intermediate.ca.pem \
        -CAkey intermediate.ca.key \
        -in mock.ds.server.csr \
        -out mock.ds.server.pem
```

---
### Merge Certificate Chain
```sh
cat mock.ds.server.pem intermediate.ca.pem root.ca.pem > mock.ds.server.chain.pem
```

---
### Test
#### Fail case
將mock.ds.server.chain.pem放到server中, 啟動後用cURL打API測試

```sh
curl -v 'https://127.0.0.1:443/hello'
*   Trying 127.0.0.1:443...
* Connected to 127.0.0.1 (127.0.0.1) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: /etc/ssl/cert.pem
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* (304) (IN), TLS handshake, Unknown (8):
* (304) (IN), TLS handshake, Certificate (11):
* SSL certificate problem: unable to get local issuer certificate
* Closing connection 0
curl: (60) SSL certificate problem: unable to get local issuer certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

/etc/ssl/cert.pem 這個路徑下並沒有上面的Issuer, 所以會判斷為`unable to get local issuer certificate`

---
#### Success case
因此需要將CA憑證提供給ClientServer
這樣就可以打通API
以上是Server有掛SSL憑證, 屬於單向驗證

```sh
curl -v 'https://127.0.0.1:443/hello' --cacert ./client_certificates/intermediate.ca.pem
*   Trying 127.0.0.1:443...
* Connected to 127.0.0.1 (127.0.0.1) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: ./certificates/intermediate.ca.pem
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* (304) (IN), TLS handshake, Unknown (8):
* (304) (IN), TLS handshake, Certificate (11):
* (304) (IN), TLS handshake, CERT verify (15):
* (304) (IN), TLS handshake, Finished (20):
* (304) (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / AEAD-AES128-GCM-SHA256
* ALPN, server accepted to use h2
* Server certificate:
*  subject: C=TW; ST=Taipei; O=ImMockDS; OU=IT; CN=127.0.0.1
*  start date: Aug 14 06:25:10 2022 GMT
*  expire date: Aug 14 06:25:10 2023 GMT
*  common name: 127.0.0.1 (matched)
*  issuer: C=TW; ST=Taipei; O=ImIntermediateca; OU=IT; CN=www.intermidateca.com
*  SSL certificate verify ok.
* Using HTTP2, server supports multiplexing
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
* Using Stream ID: 1 (easy handle 0x7fba4a012400)
> GET /hello HTTP/2
> Host: 127.0.0.1
> user-agent: curl/7.79.1
> accept: */*
>
* Connection state changed (MAX_CONCURRENT_STREAMS == 250)!
< HTTP/2 200
< content-type: text/plain; charset=utf-8
< content-length: 14
< date: Sun, 14 Aug 2022 06:50:58 GMT
<
Hello, world!
* Connection #0 to host 127.0.0.1 left intact

```


---
## Setup mTLS Part
以下開始設定mTLS

---
### Generate Client Certificate
```sh
openssl genrsa -out client.server.key 2048
openssl req -new -sha256 -key client.server.key \
        -subj "/C=TW/ST=Taipei/O=ClientServer/OU=IT/CN=127.0.0.1" \
        -out client.server.csr
```

---
### Sign client server csr
```sh
openssl x509 -req -CAcreateserial -days 365 -sha256\
        -CA intermediate.ca.pem \
        -CAkey intermediate.ca.key \
        -in ../client_certificates/client.server.csr \
        -out client.server.pem
```

---
### Merge Certificate Chain
```sh
cat client.server.pem intermediate.ca.pem root.ca.pem > client.server.chain.pem
```

---
### Test

#### Fail case
```sh
curl -v 'https://127.0.0.1:443/hello' --cacert ./certificates/intermediate.ca.pem
*   Trying 127.0.0.1:443...
* Connected to 127.0.0.1 (127.0.0.1) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: ./certificates/intermediate.ca.pem
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* (304) (IN), TLS handshake, Unknown (8):
* (304) (IN), TLS handshake, Request CERT (13):
* (304) (IN), TLS handshake, Certificate (11):
* (304) (IN), TLS handshake, CERT verify (15):
* (304) (IN), TLS handshake, Finished (20):
* (304) (OUT), TLS handshake, Certificate (11):
* (304) (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / AEAD-AES128-GCM-SHA256
* ALPN, server accepted to use h2
* Server certificate:
*  subject: C=TW; ST=Taipei; O=ImMockDS; OU=IT; CN=127.0.0.1
*  start date: Aug 14 06:25:10 2022 GMT
*  expire date: Aug 14 06:25:10 2023 GMT
*  common name: 127.0.0.1 (matched)
*  issuer: C=TW; ST=Taipei; O=ImIntermediateca; OU=IT; CN=www.intermidateca.com
*  SSL certificate verify ok.
* Using HTTP2, server supports multiplexing
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
* Using Stream ID: 1 (easy handle 0x7f826080f600)
> GET /hello HTTP/2
> Host: 127.0.0.1
> user-agent: curl/7.79.1
> accept: */*
>
* LibreSSL SSL_read: error:1404C412:SSL routines:ST_OK:sslv3 alert bad certificate, errno 0
* Failed receiving HTTP2 data
* LibreSSL SSL_write: SSL_ERROR_SYSCALL, errno 0
* Failed sending HTTP2 data
* Connection #0 to host 127.0.0.1 left intact
curl: (56) LibreSSL SSL_read: error:1404C412:SSL routines:ST_OK:sslv3 alert bad certificate, errno 0
```

---
直接用之前的方式進行呼叫, 會因為沒有回應Server的請求出示ClientSSLCertificate, 所以Handshake Failure.
Server會印出Client沒有帶憑證的資訊

```
2022/08/14 16:55:26 http: TLS handshake error from 127.0.0.1:62332: tls: client didn't provide a certificate
```

---
#### Success case
```sh
curl -v 'https://127.0.0.1:443/hello' --cacert ./client_certificates/intermediate.ca.pem --cert ./client_certificates/client.server.chain.pem --key ./client_certificates/client.server.key
*   Trying 127.0.0.1:443...
* Connected to 127.0.0.1 (127.0.0.1) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: ./client_certificates/intermediate.ca.pem
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* (304) (IN), TLS handshake, Unknown (8):
* (304) (IN), TLS handshake, Request CERT (13):
* (304) (IN), TLS handshake, Certificate (11):
* (304) (IN), TLS handshake, CERT verify (15):
* (304) (IN), TLS handshake, Finished (20):
* (304) (OUT), TLS handshake, Certificate (11):
* (304) (OUT), TLS handshake, CERT verify (15):
* (304) (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / AEAD-AES128-GCM-SHA256
* ALPN, server accepted to use h2
* Server certificate:
*  subject: C=TW; ST=Taipei; O=ImMockDS; OU=IT; CN=127.0.0.1
*  start date: Aug 14 06:25:10 2022 GMT
*  expire date: Aug 14 06:25:10 2023 GMT
*  common name: 127.0.0.1 (matched)
*  issuer: C=TW; ST=Taipei; O=ImIntermediateca; OU=IT; CN=www.intermidateca.com
*  SSL certificate verify ok.
* Using HTTP2, server supports multiplexing
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
* Using Stream ID: 1 (easy handle 0x7fbf89013600)
> GET /hello HTTP/2
> Host: 127.0.0.1
> user-agent: curl/7.79.1
> accept: */*
>
* Connection state changed (MAX_CONCURRENT_STREAMS == 250)!
< HTTP/2 200
< content-type: text/plain; charset=utf-8
< content-length: 14
< date: Sun, 14 Aug 2022 07:39:20 GMT
<
Hello, world!
* Connection #0 to host 127.0.0.1 left intact
```


---
### Issue
**Problem:**
http: TLS handshake error from 127.0.0.1:61417: tls: failed to verify client certificate: x509: certificate signed by unknown authority (possibly because of "x509: cannot verify signature: insecure algorithm SHA1-RSA (temporarily override with GODEBUG=x509sha1=1)" while trying to verify candidate authority certificate "www.intermidateca.com")

**Solution:**
原因是簽署憑證的時候如果沒指定HASH演算法, 則會使用預設的SHA1, 所以需要指定成SHA256就可以了
```sh
openssl x509 -req -CAcreateserial -days 365 -sha256\
        -CA intermediate.ca.pem \
        -CAkey intermediate.ca.key \
        -in ../client_certificates/client.server.csr \
        -out client.server.pem
```
```sh
openssl x509 -req -CAcreateserial -days 365 -sha256\
        -CA intermediate.ca.pem \
        -CAkey intermediate.ca.key \
        -in ../certificates/mock.ds.server.csr \
        -out mock.ds.server.pem
```
> https://github.com/fatedier/frp/issues/2957

---
## Wrong domain in client ssl certificate test

### Gererate wrong domain certificate
```sh
openssl req -new -sha256 -key client.server.key \
        -subj "/C=TW/ST=Taipei/O=ClientServer/OU=IT/CN=www.wrong.com" \
        -out wrong.client.server.csr
```

---
### Sign client server csr
```sh
openssl x509 -req -CAcreateserial -days 365 -sha256\
        -CA intermediate.ca.pem \
        -CAkey intermediate.ca.key \
        -in ../client_certificates/wrong.client.server.csr \
        -out wrong.client.server.pem
```

---
### Merge Certificate Chain
```sh
cat wrong.client.server.pem intermediate.ca.pem root.ca.pem > wrong.client.server.chain.pem
```

---
### Test
client ssl certificate common name is `www.wrong.com`
real domain name is `localhost`
result: handshake is success

```sh
curl -v 'https://127.0.0.1:443/hello' --cacert ./client_certificates/intermediate.ca.pem --cert ./client_certificates/wrong.client.server.chain.pem --key ./client_certificates/client.server.key
*   Trying 127.0.0.1:443...
* Connected to 127.0.0.1 (127.0.0.1) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: ./client_certificates/intermediate.ca.pem
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* (304) (IN), TLS handshake, Unknown (8):
* (304) (IN), TLS handshake, Request CERT (13):
* (304) (IN), TLS handshake, Certificate (11):
* (304) (IN), TLS handshake, CERT verify (15):
* (304) (IN), TLS handshake, Finished (20):
* (304) (OUT), TLS handshake, Certificate (11):
* (304) (OUT), TLS handshake, CERT verify (15):
* (304) (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / AEAD-AES128-GCM-SHA256
* ALPN, server accepted to use h2
* Server certificate:
*  subject: C=TW; ST=Taipei; O=ImMockDS; OU=IT; CN=127.0.0.1
*  start date: Aug 14 06:25:10 2022 GMT
*  expire date: Aug 14 06:25:10 2023 GMT
*  common name: 127.0.0.1 (matched)
*  issuer: C=TW; ST=Taipei; O=ImIntermediateca; OU=IT; CN=www.intermidateca.com
*  SSL certificate verify ok.
* Using HTTP2, server supports multiplexing
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
* Using Stream ID: 1 (easy handle 0x7f94d1011e00)
> GET /hello HTTP/2
> Host: 127.0.0.1
> user-agent: curl/7.79.1
> accept: */*
>
* Connection state changed (MAX_CONCURRENT_STREAMS == 250)!
< HTTP/2 200
< content-type: text/plain; charset=utf-8
< content-length: 14
< date: Sun, 14 Aug 2022 07:49:22 GMT
<
Hello, world!
* Connection #0 to host 127.0.0.1 left intact
```

---
## Wrong domain in server ssl certificate test
```sh
openssl req -new -sha256 -key mock.ds.server.key \
        -subj "/C=TW/ST=Taipei/O=ImMockDS/OU=IT/CN=www.wrongdomain.com" \
        -out wrong.mock.ds.server.csr

openssl x509 -req -CAcreateserial -days 365 -sha256\
        -CA intermediate.ca.pem \
        -CAkey intermediate.ca.key \
        -in wrong.mock.ds.server.csr \
        -out wrong.mock.ds.server.pem

cat wrong.mock.ds.server.pem intermediate.ca.pem root.ca.pem > wrong.mock.ds.server.chain.pem
```

---
### Test
server ssl certificate common name is `www.wrongdomain.com`
real domain name is `localhost`
result: handshake is failure.
```sh
curl -v 'https://127.0.0.1:443/hello' --cacert ./client_certificates/intermediate.ca.pem --cert ./client_certificates/wrong.client.server.chain.pem --key ./client_certificates/client.server.key
*   Trying 127.0.0.1:443...
* Connected to 127.0.0.1 (127.0.0.1) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: ./client_certificates/intermediate.ca.pem
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
* (304) (IN), TLS handshake, Unknown (8):
* (304) (IN), TLS handshake, Request CERT (13):
* (304) (IN), TLS handshake, Certificate (11):
* (304) (IN), TLS handshake, CERT verify (15):
* (304) (IN), TLS handshake, Finished (20):
* (304) (OUT), TLS handshake, Certificate (11):
* (304) (OUT), TLS handshake, CERT verify (15):
* (304) (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / AEAD-AES128-GCM-SHA256
* ALPN, server accepted to use h2
* Server certificate:
*  subject: C=TW; ST=Taipei; O=ImMockDS; OU=IT; CN=www.wrongdomain.com
*  start date: Aug 14 07:58:59 2022 GMT
*  expire date: Aug 14 07:58:59 2023 GMT
* SSL: certificate subject name 'www.wrongdomain.com' does not match target host name '127.0.0.1'
* Closing connection 0
curl: (60) SSL: certificate subject name 'www.wrongdomain.com' does not match target host name '127.0.0.1'
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

---
## Test client using Server certificate
測試Client使用Server憑證是否可以成功通過Server的mTLS檢查

```sh
curl -v 'https://127.0.0.1:443/hello' --cacert ./certificates/intermediate.ca.pem --cert ./certificates/mock.ds.server.chain.pem --key ./certificates/mock.ds.server.key
*   Trying 127.0.0.1:443...
* Connected to 127.0.0.1 (127.0.0.1) port 443 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*  CAfile: ./certificates/intermediate.ca.pem
*  CApath: none
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
* TLSv1.2 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Request CERT (13):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Certificate (11):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS handshake, CERT verify (15):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-CHACHA20-POLY1305
* ALPN, server accepted to use h2
* Server certificate:
*  subject: C=TW; ST=Taipei; O=ImMockDS; OU=IT; CN=127.0.0.1
*  start date: Aug 14 06:25:10 2022 GMT
*  expire date: Aug 14 06:25:10 2023 GMT
*  common name: 127.0.0.1 (matched)
*  issuer: C=TW; ST=Taipei; O=ImIntermediateca; OU=IT; CN=www.intermidateca.com
*  SSL certificate verify ok.
* Using HTTP2, server supports multi-use
* Connection state changed (HTTP/2 confirmed)
* Copying HTTP/2 data in stream buffer to connection buffer after upgrade: len=0
* Using Stream ID: 1 (easy handle 0x11f812400)
> GET /hello HTTP/2
> Host: 127.0.0.1
> user-agent: curl/7.77.0
> accept: */*
>
* Connection state changed (MAX_CONCURRENT_STREAMS == 250)!
< HTTP/2 200
< content-type: text/plain; charset=utf-8
< content-length: 14
< date: Fri, 16 Sep 2022 04:44:09 GMT
<
Hello, world!
* Connection #0 to host 127.0.0.1 left intact
```