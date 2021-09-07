// Code generated by bpf2go; DO NOT EDIT.
// +build 386 amd64 amd64p32 arm arm64 mipsle mips64le mips64p32le ppc64le riscv64

package main

import (
	"bytes"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadFlowsnoop returns the embedded CollectionSpec for flowsnoop.
func loadFlowsnoop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_FlowsnoopBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load flowsnoop: %w", err)
	}

	return spec, err
}

// loadFlowsnoopObjects loads flowsnoop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *flowsnoopObjects
//     *flowsnoopPrograms
//     *flowsnoopMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadFlowsnoopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadFlowsnoop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// flowsnoopSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type flowsnoopSpecs struct {
	flowsnoopProgramSpecs
	flowsnoopMapSpecs
}

// flowsnoopSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type flowsnoopProgramSpecs struct {
	TracepointNetNetDevStartXmit *ebpf.ProgramSpec `ebpf:"tracepoint__net_net_dev_start_xmit"`
	TracepointNetNetifReceiveSkb *ebpf.ProgramSpec `ebpf:"tracepoint__net_netif_receive_skb"`
}

// flowsnoopMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type flowsnoopMapSpecs struct {
	Bconnections  *ebpf.MapSpec `ebpf:"bconnections"`
	Bconnections6 *ebpf.MapSpec `ebpf:"bconnections6"`
	ConfigMap     *ebpf.MapSpec `ebpf:"config_map"`
	Connections   *ebpf.MapSpec `ebpf:"connections"`
	Connections6  *ebpf.MapSpec `ebpf:"connections6"`
	Events        *ebpf.MapSpec `ebpf:"events"`
}

// flowsnoopObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadFlowsnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type flowsnoopObjects struct {
	flowsnoopPrograms
	flowsnoopMaps
}

func (o *flowsnoopObjects) Close() error {
	return _FlowsnoopClose(
		&o.flowsnoopPrograms,
		&o.flowsnoopMaps,
	)
}

// flowsnoopMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadFlowsnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type flowsnoopMaps struct {
	Bconnections  *ebpf.Map `ebpf:"bconnections"`
	Bconnections6 *ebpf.Map `ebpf:"bconnections6"`
	ConfigMap     *ebpf.Map `ebpf:"config_map"`
	Connections   *ebpf.Map `ebpf:"connections"`
	Connections6  *ebpf.Map `ebpf:"connections6"`
	Events        *ebpf.Map `ebpf:"events"`
}

func (m *flowsnoopMaps) Close() error {
	return _FlowsnoopClose(
		m.Bconnections,
		m.Bconnections6,
		m.ConfigMap,
		m.Connections,
		m.Connections6,
		m.Events,
	)
}

// flowsnoopPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadFlowsnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type flowsnoopPrograms struct {
	TracepointNetNetDevStartXmit *ebpf.Program `ebpf:"tracepoint__net_net_dev_start_xmit"`
	TracepointNetNetifReceiveSkb *ebpf.Program `ebpf:"tracepoint__net_netif_receive_skb"`
}

func (p *flowsnoopPrograms) Close() error {
	return _FlowsnoopClose(
		p.TracepointNetNetDevStartXmit,
		p.TracepointNetNetifReceiveSkb,
	)
}

func _FlowsnoopClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.