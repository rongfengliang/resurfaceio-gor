# resurfaceio-gor
resurfaceio-gor


## support cli

```code
Gor is a simple http traffic replication tool written in Go. Its main goal is to replay traffic from production servers to staging and dev environments.
Project page: https://github.com/buger/gor
Author: <Leonid Bugaev> leonsbox@gmail.com
Current Version: v1.4.3-Resurface

  -copy-buffer-size value
    	Set the buffer size for an individual request (default 5MB)
  -cpuprofile string
    	write cpu profile to file
  -exit-after duration
    	exit after specified duration
  -http-allow-header value
    	A regexp to match a specific header against. Requests with non-matching headers will be dropped:
    		 gor --input-raw :8080 --output-http staging.com --http-allow-header api-version:^v1
  -http-allow-method value
    	Whitelist of HTTP methods to replay. Anything else will be dropped:
    		gor --input-raw :8080 --output-http staging.com --http-allow-method GET --http-allow-method OPTIONS
  -http-allow-url value
    	A regexp to match requests against. Filter get matched against full url with domain. Anything else will be dropped:
    		 gor --input-raw :8080 --output-http staging.com --http-allow-url ^www.
  -http-basic-auth-filter value
    	A regexp to match the decoded basic auth string against. Requests with non-matching headers will be dropped:
    		 gor --input-raw :8080 --output-http staging.com --http-basic-auth-filter "^customer[0-9].*"
  -http-disallow-header value
    	A regexp to match a specific header against. Requests with matching headers will be dropped:
    		 gor --input-raw :8080 --output-http staging.com --http-disallow-header "User-Agent: Replayed by Gor"
  -http-disallow-url value
    	A regexp to match requests against. Filter get matched against full url with domain. Anything else will be forwarded:
    		 gor --input-raw :8080 --output-http staging.com --http-disallow-url ^www.
  -http-header-limiter value
    	Takes a fraction of requests, consistently taking or rejecting a request based on the FNV32-1A hash of a specific header:
    		 gor --input-raw :8080 --output-http staging.com --http-header-limiter user-id:25%
  -http-original-host
    	Normally gor replaces the Host http header with the host supplied with --output-http.  This option disables that behavior, preserving the original Host header.
  -http-param-limiter value
    	Takes a fraction of requests, consistently taking or rejecting a request based on the FNV32-1A hash of a specific GET param:
    		 gor --input-raw :8080 --output-http staging.com --http-param-limiter user_id:25%
  -http-pprof :8181
    	Enable profiling. Starts  http server on specified port, exposing special /debug/pprof endpoint. Example: :8181
  -http-rewrite-header value
    	Rewrite the request header based on a mapping:
    		gor --input-raw :8080 --output-http staging.com --http-rewrite-header Host: (.*).example.com,$1.beta.example.com
  -http-rewrite-url value
    	Rewrite the request url based on a mapping:
    		gor --input-raw :8080 --output-http staging.com --http-rewrite-url /v1/user/([^\/]+)/ping:/v2/user/$1/ping
  -http-set-header value
    	Inject additional headers to http request:
    		gor --input-raw :8080 --output-http staging.com --http-set-header 'User-Agent: Gor'
  -http-set-param value
    	Set request url param, if param already exists it will be overwritten:
    		gor --input-raw :8080 --output-http staging.com --http-set-param api_key=1
  -input-dummy value
    	Used for testing outputs. Emits 'Get /' request every 1s (default [])
  -input-file value
    	Read requests from file:
    		gor --input-file ./requests.gor --output-http staging.com (default [])
  -input-file-dry-run
    	Simulate reading from the data source without replaying it. You will get information about expected replay time, number of found records etc.
  -input-file-loop
    	Loop input files, useful for performance testing.
  -input-file-max-wait duration
    	Set the maximum time between requests. Can help in situations when you have too long periods between request, and you want to skip them. Example: --input-raw-max-wait 1s
  -input-file-read-depth int
    	GoReplay tries to read and cache multiple records, in advance. In parallel it also perform sorting of requests, if they came out of order. Since it needs hold this buffer in memory, bigger values can cause worse performance (default 100)
  -input-kafka-host string
    	Send request and response stats to Kafka:
    		gor --output-stdout --input-kafka-host '192.168.0.1:9092,192.168.0.2:9092'
  -input-kafka-json-format
    	If turned on, it will assume that messages coming in JSON format rather than  GoReplay text format.
  -input-kafka-mechanism string
    	mechanism
    		gor --input-raw :8080 --output-kafka-mechanism 'SCRAM-SHA-512'
  -input-kafka-password string
    	password
    		gor --input-raw :8080 --output-kafka-password 'password'
  -input-kafka-topic string
    	Send request and response stats to Kafka:
    		gor --output-stdout --input-kafka-topic 'kafka-log'
  -input-kafka-use-sasl
    	use-sasl
    		--use-sasl true
  -input-kafka-username string
    	username
    		gor --input-raw :8080 --output-kafka-username 'username'
  -input-raw value
    	Capture traffic from given port (use RAW sockets and require *sudo* access):
    		# Capture traffic from 8080 port
    		gor --input-raw :8080 --output-http staging.com (default [])
  -input-raw-allow-incomplete
    	If turned on Gor will record HTTP messages with missing packets
  -input-raw-bpf-filter string
    	BPF filter to write custom expressions. Can be useful in case of non standard network interfaces like tunneling or SPAN port. Example: --input-raw-bpf-filter 'dst port 80'
  -input-raw-buffer-size value
    	Controls size of the OS buffer which holds packets until they dispatched. Default value depends by system: in Linux around 2MB. If you see big package drop, increase this value.
  -input-raw-buffer-timeout duration
    	set the pcap timeout. for immediate mode don't set this flag
  -input-raw-engine libpcap
    	Intercept traffic using libpcap (default), `raw_socket`, `pcap_file`, `vxlan`
  -input-raw-expire duration
    	How much it should wait for the last TCP packet, till consider that TCP message complete. (default 2s)
  -input-raw-ignore-interface value
    	In case if you want listen for all interfaces except a few ones. Can be used in k8s environment. Example: --input-raw-ignore-interface cbr0 --input-raw-ignore-interface eth0 --input-raw-ignore-interface localhost (default [])
  -input-raw-k8s-nomatch-nocap
    	disable port-only capture mode when no matching pods are found in the cluster
  -input-raw-k8s-skip-ns value
    	skip k8s these namespaces for discovery. Example: --input-raw-k8s-skip-ns kube-system (default [])
  -input-raw-k8s-skip-svc value
    	skip k8s these services for discovery. Example: --input-raw-k8s-skip-svc kubernetes (default [])
  -input-raw-monitor
    	enable RF monitor mode
  -input-raw-override-snaplen
    	Override the capture snaplen to be 64k. Required for some Virtualized environments
  -input-raw-promisc
    	enable promiscuous mode
  -input-raw-protocol value
    	Specify application protocol of intercepted traffic. Possible values: http, binary
  -input-raw-realip-header string
    	If not blank, injects header with given name and real IP value to the request payload. Usually this header should be named: X-Real-IP
  -input-raw-stats
    	enable stats generator on raw TCP messages
  -input-raw-timestamp-type string
    	Possible values: PCAP_TSTAMP_HOST, PCAP_TSTAMP_HOST_LOWPREC, PCAP_TSTAMP_HOST_HIPREC, PCAP_TSTAMP_ADAPTER, PCAP_TSTAMP_ADAPTER_UNSYNCED. This values not supported on all systems, GoReplay will tell you available values of you put wrong one.
  -input-raw-track-response
    	If turned on Gor will track responses in addition to requests, and they will be available to middleware and file output.
  -input-raw-vlan
    	Enable VLAN (802.1Q) support
  -input-raw-vlan-vid value
    	VLAN VID to capture. By default capture all VIDs (default [])
  -input-raw-vxlan-port vxlan
    	VXLAN port. Can be used only when engine set to vxlan. Default: 4789 (default 4789)
  -input-raw-vxlan-vni --input-raw-vxlan-vni -2
    	VXLAN VNI to capture. By default capture all VNIs. Ignore VNI by setting them with minus sign, example: --input-raw-vxlan-vni -2 (default [])
  -input-tcp value
    	Used for internal communication between Gor instances. Example:
    		# Receive requests from other Gor instances on 28020 port, and redirect output to staging
    		gor --input-tcp :28020 --output-http staging.com (default [])
  -input-tcp-certificate string
    	Path to PEM encoded certificate file. Used when TLS turned on.
  -input-tcp-certificate-key string
    	Path to PEM encoded certificate key file. Used when TLS turned on.
  -input-tcp-secure
    	Turn on TLS security. Do not forget to specify certificate and key files.
  -kafka-tls-ca-cert string
    	CA certificate for Kafka TLS Config:
    		gor  --input-raw :3000 --output-kafka-host '192.168.0.1:9092' --output-kafka-topic 'topic' --kafka-tls-ca-cert cacert.cer.pem --kafka-tls-client-cert client.cer.pem --kafka-tls-client-key client.key.pem
  -kafka-tls-client-cert string
    	Client certificate for Kafka TLS Config (mandatory with to kafka-tls-ca-cert and kafka-tls-client-key)
  -kafka-tls-client-key string
    	Client Key for Kafka TLS Config (mandatory with to kafka-tls-client-cert and kafka-tls-client-key)
  -memprofile string
    	write memory profile to this file
  -middleware string
    	Used for modifying traffic using external command
  -output-binary value
    	Forwards incoming binary payloads to given address.
    		# Redirect all incoming requests to staging.com address
    		gor --input-raw :80 --input-raw-protocol binary --output-binary staging.com:80 (default [])
  -output-binary-debug
    	Enables binary debug output.
  -output-binary-timeout duration
    	Specify HTTP request/response timeout. By default 5s. Example: --output-binary-timeout 30s
  -output-binary-track-response
    	If turned on, Binary output responses will be set to all outputs like stdout, file and etc.
  -output-binary-workers int
    	Gor uses dynamic worker scaling by default.  Enter a number to run a set number of workers.
  -output-file value
    	Write incoming requests to file:
    		gor --input-raw :80 --output-file ./requests.gor (default [])
  -output-file-append
    	The flushed chunk is appended to existence file or not.
  -output-file-buffer string
    	The path for temporary storing current buffer:
    		gor --input-raw :80 --output-file s3://mybucket/logs/%Y-%m-%d.gz --output-file-buffer /mnt/logs (default "/tmp")
  -output-file-flush-interval duration
    	Interval for forcing buffer flush to the file, default: 1s. (default 1s)
  -output-file-max-size-limit value
    	Max size of output file, Default: 1TB
  -output-file-queue-limit int
    	The length of the chunk queue. Default: 256 (default 256)
  -output-file-size-limit value
    	Size of each chunk. Default: 32mb
  -output-http value
    	Forwards incoming requests to given http address.
    		# Redirect all incoming requests to staging.com address
    		gor --input-raw :80 --output-http http://staging.com (default [])
  -output-http-elasticsearch string
    	Send request and response stats to ElasticSearch:
    		gor --input-raw :8080 --output-http staging.com --output-http-elasticsearch 'es_host:api_port/index_name'
  -output-http-queue-len int
    	Number of requests that can be queued for output, if all workers are busy. default = 1000 (default 1000)
  -output-http-redirects int
    	Enable how often redirects should be followed.
  -output-http-response-buffer value
    	HTTP response buffer size, all data after this size will be discarded.
  -output-http-skip-verify
    	Don't verify hostname on TLS secure connection.
  -output-http-stats
    	Report http output queue stats to console every N milliseconds. See output-http-stats-ms
  -output-http-stats-ms int
    	Report http output queue stats to console every N milliseconds. default: 5000 (default 5000)
  -output-http-timeout duration
    	Specify HTTP request/response timeout. By default 5s. Example: --output-http-timeout 30s (default 5s)
  -output-http-track-response
    	If turned on, HTTP output responses will be set to all outputs like stdout, file and etc.
  -output-http-worker-timeout duration
    	Duration to rollback idle workers. (default 2s)
  -output-http-workers int
    	Gor uses dynamic worker scaling. Enter a number to set a maximum number of workers. default = 0 = unlimited.
  -output-http-workers-min int
    	Gor uses dynamic worker scaling. Enter a number to set a minimum number of workers. default = 1.
  -output-kafka-host string
    	Read request and response stats from Kafka:
    		gor --input-raw :8080 --output-kafka-host '192.168.0.1:9092,192.168.0.2:9092'
  -output-kafka-json-format
    	If turned on, it will serialize messages from GoReplay text format to JSON.
  -output-kafka-mechanism string
    	mechanism
    		gor --input-raw :8080 --output-kafka-mechanism 'SCRAM-SHA-512'
  -output-kafka-password string
    	password
    		gor --input-raw :8080 --output-kafka-password 'password'
  -output-kafka-topic string
    	Read request and response stats from Kafka:
    		gor --input-raw :8080 --output-kafka-topic 'kafka-log'
  -output-kafka-use-sasl
    	--output-kafka-use-sasl true
  -output-kafka-username string
    	username
    		gor --input-raw :8080 --output-kafka-username 'username'
  -output-null
    	Used for testing inputs. Drops all requests.
  -output-resurface value
    	Forwards incoming requests and response data to resurface instance. Example: gor --input-raw :80 --output-resurface http://localhost:7701/message (default [])
  -output-resurface-rules string
    	Resurface filtering rules. Example: gor --input-raw :80 --output-resurface http://localhost:7701/message --output-resurface-rules "include_debug
    	"
  -output-stdout
    	Used for testing inputs. Just prints to console data coming from inputs.
  -output-tcp value
    	Used for internal communication between Gor instances. Example:
    		# Listen for requests on 80 port and forward them to other Gor instance on 28020 port
    		gor --input-raw :80 --output-tcp replay.local:28020 (default [])
  -output-tcp-response-buffer value
    	TCP response buffer size, all data after this size will be discarded.
  -output-tcp-secure
    	Use TLS secure connection. --input-file on another end should have TLS turned on as well.
  -output-tcp-skip-verify
    	Don't verify hostname on TLS secure connection.
  -output-tcp-stats
    	Report TCP output queue stats to console every 5 seconds.
  -output-tcp-sticky
    	Use Sticky connection. Request/Response with same ID will be sent to the same connection.
  -output-tcp-workers int
    	Number of parallel tcp connections, default is 10 (default 10)
  -output-ws value
    	Just like output tcp, just with WebSocket. Example:
    		# Listen for requests on 80 port and forward them to other Gor instance on 28020 port
    		gor --input-raw :80 --output-ws wss://replay.local:28020/endpoint (default [])
  -output-ws-skip-verify
    	Don't verify hostname on TLS secure connection.
  -output-ws-stats
    	Report WebSocket output queue stats to console every 5 seconds.
  -output-ws-sticky
    	Use Sticky connection. Request/Response with same ID will be sent to the same connection.
  -output-ws-workers int
    	Number of parallel ws connections, default is 10 (default 10)
  -prettify-http
    	If enabled, will automatically decode requests and responses with: Content-Encoding: gzip and Transfer-Encoding: chunked. Useful for debugging, in conjunction with --output-stdout
  -recognize-tcp-sessions
    	[PRO] If turned on http output will create separate worker for each TCP session. Splitting output will session based as well.
  -split-output true
    	By default each output gets same traffic. If set to true it splits traffic equally among all outputs.
  -stats
    	Turn on queue stats output
  -verbose int
    	set the level of verbosity, if greater than zero then it will turn on debug output
```
