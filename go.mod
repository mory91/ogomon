module ogomon

go 1.18

require (
	github.com/cilium/ebpf v0.11.0
	github.com/google/gopacket v1.1.19
	github.com/prometheus/procfs v0.7.3
	github.com/spf13/cobra v1.4.0
	github.com/spf13/jwalterweatherman v1.1.0
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/sys v0.6.0
)

require (
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
)

replace github.com/google/gopacket => github.com/mory91/gopacket latest
