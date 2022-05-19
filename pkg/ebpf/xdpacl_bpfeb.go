// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type xdpACLPacketFrame struct {
	Ktime      uint64
	PacketSize uint64
}

// loadXdpACL returns the embedded CollectionSpec for xdpACL.
func loadXdpACL() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_XdpACLBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load xdpACL: %w", err)
	}

	return spec, err
}

// loadXdpACLObjects loads xdpACL and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *xdpACLObjects
//     *xdpACLPrograms
//     *xdpACLMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadXdpACLObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadXdpACL()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// xdpACLSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdpACLSpecs struct {
	xdpACLProgramSpecs
	xdpACLMapSpecs
}

// xdpACLSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdpACLProgramSpecs struct {
	TcSay *ebpf.ProgramSpec `ebpf:"tc_say"`
}

// xdpACLMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xdpACLMapSpecs struct {
	PacketFrameHolder *ebpf.MapSpec `ebpf:"packet_frame_holder"`
	PortHolder        *ebpf.MapSpec `ebpf:"port_holder"`
}

// xdpACLObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadXdpACLObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdpACLObjects struct {
	xdpACLPrograms
	xdpACLMaps
}

func (o *xdpACLObjects) Close() error {
	return _XdpACLClose(
		&o.xdpACLPrograms,
		&o.xdpACLMaps,
	)
}

// xdpACLMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadXdpACLObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdpACLMaps struct {
	PacketFrameHolder *ebpf.Map `ebpf:"packet_frame_holder"`
	PortHolder        *ebpf.Map `ebpf:"port_holder"`
}

func (m *xdpACLMaps) Close() error {
	return _XdpACLClose(
		m.PacketFrameHolder,
		m.PortHolder,
	)
}

// xdpACLPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadXdpACLObjects or ebpf.CollectionSpec.LoadAndAssign.
type xdpACLPrograms struct {
	TcSay *ebpf.Program `ebpf:"tc_say"`
}

func (p *xdpACLPrograms) Close() error {
	return _XdpACLClose(
		p.TcSay,
	)
}

func _XdpACLClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed xdpacl_bpfeb.o
var _XdpACLBytes []byte
