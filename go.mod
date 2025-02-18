module github.com/lowRISC/opentitan-provisioning

go 1.19

replace github.com/lowRISC/opentitan-provisioning => ./

require (
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.6
	github.com/google/tink/go v1.6.1
	github.com/miekg/pkcs11 v1.0.3
	go.etcd.io/etcd v3.3.27+incompatible
	go.etcd.io/etcd/api/v3 v3.5.1
	go.etcd.io/etcd/client/v3 v3.5.1
	golang.org/x/crypto v0.23.0
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.0.0-20211019181941-9d821ace8654
	golang.org/x/tools v0.10.0
	google.golang.org/api v0.32.0
	google.golang.org/grpc v1.41.0

	// Required by etcd.
	github.com/coreos/go-semver v0.3.0
	github.com/coreos/go-systemd/v22 v22.3.2
	go.etcd.io/etcd/client/pkg/v3 v3.5.1
	go.uber.org/atomic v1.7.0
	go.uber.org/multierr v1.6.0
	go.uber.org/zap v1.17.0

	// Required by google.golang.org/grpc
	google.golang.org/genproto v0.0.0-20210602131652-f16073e35f0c
)

