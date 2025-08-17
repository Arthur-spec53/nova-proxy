module nova-proxy

go 1.23.12

require (
	github.com/bshuster-repo/logrus-logstash-hook v1.1.0
	github.com/cloudflare/circl v1.6.1
	github.com/fsnotify/fsnotify v1.9.0
	github.com/prometheus/client_golang v1.23.0
	github.com/qdeconinck/mp-quic v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.10.0
	golang.org/x/crypto v0.41.0
	golang.org/x/sys v0.35.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bifurcation/mint v0.0.0-20210616192047-fd18df995463 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lucas-clemente/aes12 v0.0.0-20171027163421-cd47fb39b79f // indirect
	github.com/lucas-clemente/fnv128a v0.0.0-20160504152609-393af48d3916 // indirect
	github.com/lucas-clemente/quic-go-certificates v0.0.0-20160823095156-d2f86524cced // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/qdeconinck/mp-quic => ./mp-quic
