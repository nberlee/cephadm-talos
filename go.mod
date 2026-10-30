module github.com/nberlee/cephadm-talos

go 1.27.2

require (
	github.com/cosi-project/runtime v1.16.3
	github.com/distribution/reference v0.6.0
	github.com/siderolabs/talos/pkg/machinery v1.15.0-alpha.2
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	cel.dev/cel-go v0.33.0 // indirect
	cel.dev/expr v0.25.3 // indirect
	github.com/ProtonMail/go-crypto v1.5.2 // indirect
	github.com/ProtonMail/gopenpgp/v3 v3.5.2 // indirect
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.4 // indirect
	github.com/containerd/go-cni v1.1.14 // indirect
	github.com/containernetworking/cni v1.3.1 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/evanphx/json-patch v5.9.11+incompatible // indirect
	github.com/gertd/go-pluralize v0.2.1 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-containerregistry v0.22.1 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.32.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/jsimonetti/rtnetlink/v2 v2.2.1-0.20260802200809-43bafec815b3 // indirect
	github.com/mdlayher/ethtool v0.6.1 // indirect
	github.com/mdlayher/genetlink v1.4.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.8.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/runtime-spec v1.3.0 // indirect
	github.com/petermattis/goid v0.0.0-20260918085751-abfca077860b // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20260702190614-8ae5a48058df // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/sasha-s/go-deadlock v0.3.9 // indirect
	github.com/siderolabs/crypto v0.6.5 // indirect
	github.com/siderolabs/gen v0.8.8 // indirect
	github.com/siderolabs/go-api-signature v0.4.0 // indirect
	github.com/siderolabs/go-pointer v1.0.1 // indirect
	github.com/siderolabs/net v0.4.0 // indirect
	github.com/siderolabs/protoenc v0.2.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.6 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261026165753-2ffab32bce7e // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261026165753-2ffab32bce7e // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/utils v0.0.0-20261023123148-ca04ba58ecab // indirect
)

replace github.com/siderolabs/talos/pkg/machinery => github.com/nberlee/talos/pkg/machinery v0.0.0-20261030085331-8ee5a247ecc6
