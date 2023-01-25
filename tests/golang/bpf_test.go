// +build integration

// Copyright 2016 PLUMgrid
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"
	"github.com/iovisor/gobpf/elf"
	"github.com/iovisor/gobpf/pkg/bpffs"
	"github.com/iovisor/gobpf/pkg/progtestrun"
)

// redefine flags here as cgo in test is not supported
const (
	BPF_ANY     = 0 /* create new element or update existing */
	BPF_NOEXIST = 1 /* create new element if it didn't exist */
	BPF_EXIST   = 2
)

var simple1 string = `
BPF_TABLE("hash", int, int, table1, 10);
int func1(void *ctx) {
	return 0;
}
`

var simple2 = `
struct key {
  int key;
};
struct leaf {
  int value;
};
BPF_HASH(table2, struct key, struct leaf, 10);
int func2(void *ctx) {
	return 0;
}
`

type key struct {
	key uint32
}

type leaf struct {
	value uint32
}

var kernelVersion uint32

var (
	kernelVersion46  uint32
	kernelVersion47  uint32
	kernelVersion48  uint32
	kernelVersion410 uint32
	kernelVersion412 uint32
	kernelVersion414 uint32
)

func init() {
	kernelVersion46, _ = elf.KernelVersionFromReleaseString("4.6.0")
	kernelVersion47, _ = elf.KernelVersionFromReleaseString("4.7.0")
	kernelVersion48, _ = elf.KernelVersionFromReleaseString("4.8.0")
	kernelVersion410, _ = elf.KernelVersionFromReleaseString("4.10.0")
	kernelVersion412, _ = elf.KernelVersionFromReleaseString("4.12.0")
	kernelVersion414, _ = elf.KernelVersionFromReleaseString("4.14.0")
}

func TestModuleLoadBCC(t *testing.T) {
	b := bcc.NewModule(simple1, []string{})
	if b == nil {
		t.Fatal("prog is nil")
	}
	defer b.Close()
	_, err := b.LoadKprobe("func1")
	if err != nil {
		t.Fatal(err)
	}
}

func fillTable1(b *bcc.Module) (*bcc.Table, error) {
	table := bcc.NewTable(b.TableId("table1"), b)
	key, _ := table.KeyStrToBytes("1")
	leaf, _ := table.LeafStrToBytes("11")
	if err := table.Set(key, leaf); err != nil {
		return nil, fmt.Errorf("table.Set key 1 failed: %v", err)
	}

	key, leaf = make([]byte, 4), make([]byte, 4)
	bcc.GetHostByteOrder().PutUint32(key, 2)
	bcc.GetHostByteOrder().PutUint32(leaf, 22)
	if err := table.Set(key, leaf); err != nil {
		return nil, fmt.Errorf("table.Set key 2 failed: %v", err)
	}

	return table, nil
}

func TestBCCIterTable(t *testing.T) {
	b := bcc.NewModule(simple1, []string{})
	if b == nil {
		t.Fatal("prog is nil")
	}
	defer b.Close()

	table, err := fillTable1(b)
	if err != nil {
		t.Fatalf("fill table1 failed: %v", err)
	}

	hostEndian := bcc.GetHostByteOrder()
	resIter := make(map[int32]int32)
	iter := table.Iter()
	for iter.Next() {
		key, leaf := iter.Key(), iter.Leaf()
		keyStr, err := table.KeyBytesToStr(key)
		if err != nil {
			t.Fatalf("table.Iter/KeyBytesToStr failed: cannot print value: %v", err)
		}
		leafStr, err := table.LeafBytesToStr(leaf)
		if err != nil {
			t.Fatalf("table.Iter/LeafBytesToStr failed: cannot print value: %v", err)
		}

		var k, v int32
		if err := binary.Read(bytes.NewBuffer(key), hostEndian, &k); err != nil {
			t.Fatalf("table.Iter failed: cannot decode key: %v", err)
		}
		if err := binary.Read(bytes.NewBuffer(leaf), hostEndian, &v); err != nil {
			t.Fatalf("table.Iter failed: cannot decode value: %v", err)
		}

		resIter[k] = v

		kS, err := strconv.ParseInt(keyStr[2:], 16, 32)
		if err != nil {
			t.Fatalf("table.Iter failed: non-number key: %v", err)
		}
		vS, err := strconv.ParseInt(leafStr[2:], 16, 32)
		if err != nil {
			t.Fatalf("table.Iter failed: non-number value: %v", err)
		}

		if int32(kS) != k || int32(vS) != v {
			t.Errorf("table.iter.Values() inconsistent with string values: (%v, %v) vs (%v, %v)", k, v, kS, vS)
		}
	}

	if iter.Err() != nil {
		t.Fatalf("table.Iter failed: iteration finished with unexpected error: %v", iter.Err())
	}

	if count := len(resIter); count != 2 {
		t.Fatalf("expected 2 entries in Iter table, not %d", count)
	}

	for _, te := range [][]int32{{1, 11}, {2, 22}} {
		res := resIter[te[0]]
		if res != te[1] {
			t.Fatalf("expected entry %d in Iter table to contain %d, but got %d", te[0], te[1], res)
		}
	}
}

func TestBCCTableSetPGetPDeleteP(t *testing.T) {
	b := bcc.NewModule(simple2, []string{})
	if b == nil {
		t.Fatal("prog is nil")
	}
	defer b.Close()

	table := bcc.NewTable(b.TableId("table2"), b)

	k := &key{0}
	l := &leaf{1}

	err := table.SetP(unsafe.Pointer(k), unsafe.Pointer(l))
	if err != nil {
		t.Fatal(err)
	}

	p, err := table.GetP(unsafe.Pointer(k))
	if err != nil {
		t.Fatal(err)
	}
	v := (*leaf)(p)
	if v.value != 1 {
		t.Fatalf("expected 1, not %d", v.value)
	}

	err = table.DeleteP(unsafe.Pointer(k))
	if err != nil {
		t.Fatal(err)
	}

	_, err = table.GetP(unsafe.Pointer(k))
	if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestBCCTableDeleteAll(t *testing.T) {
	b := bcc.NewModule(simple1, []string{})
	if b == nil {
		t.Fatal("prog is nil")
	}
	defer b.Close()

	table, err := fillTable1(b)
	if err != nil {
		t.Fatalf("fill table1 failed: %v", err)
	}

	count := 0
	for it := table.Iter(); it.Next(); {
		count++
	}
	if count != 2 {
		t.Fatalf("expected 2 entries in table, not %d", count)
	}
	if err := table.DeleteAll(); err != nil {
		t.Fatalf("table.DeleteAll failed: %v", err)
	}
	count = 0
	for it := table.Iter(); it.Next(); {
		count++
	}
	if count != 0 {
		t.Fatalf("expected 0 entries in table, not %d", count)
	}
}

func containsMap(maps []*elf.Map, name string) bool {
	for _, m := range maps {
		if m.Name == name {
			return true
		}
	}
	return false
}

func containsProbe(probes []*elf.Kprobe, name string) bool {
	for _, k := range probes {
		if k.Name == name {
			return true
		}
	}
	return false
}

func containsUprobe(uprobes []*elf.Uprobe, name string) bool {
	for _, u := range uprobes {
		if u.Name == name {
			return true
		}
	}
	return false
}

func containsCgroupProg(cgroupProgs []*elf.CgroupProgram, name string) bool {
	for _, c := range cgroupProgs {
		if c.Name == name {
			return true
		}
	}
	return false
}

func containsTracepointProg(tracepointProgs []*elf.TracepointProgram, name string) bool {
	for _, c := range tracepointProgs {
		if c.Name == name {
			return true
		}
	}
	return false
}

func containsSocketFilter(socketFilters []*elf.SocketFilter, name string) bool {
	for _, c := range socketFilters {
		if c.Name == name {
			return true
		}
	}
	return false
}

func checkMaps(t *testing.T, b *elf.Module) {
	var expectedMaps = []string{
		"dummy_hash",
		"dummy_array",
		"dummy_prog_array",
		"dummy_perf",
		"dummy_array_custom",
	}

	if kernelVersion >= kernelVersion46 {
		kernel46Maps := []string{
			"dummy_percpu_hash",
			"dummy_percpu_array",
			"dummy_stack_trace",
		}
		expectedMaps = append(expectedMaps, kernel46Maps...)
	} else {
		t.Logf("kernel doesn't support percpu maps and stacktrace maps. Skipping...")
	}

	if kernelVersion >= kernelVersion48 {
		kernel48Maps := []string{
			"dummy_cgroup_array",
		}
		expectedMaps = append(expectedMaps, kernel48Maps...)
	} else {
		t.Logf("kernel doesn't support cgroup array maps. Skipping...")
	}

	var maps []*elf.Map
	for m := range b.IterMaps() {
		maps = append(maps, m)
	}
	if len(maps) != len(expectedMaps) {
		t.Fatalf("unexpected number of maps. Got %d, expected %d", len(maps), len(expectedMaps))
	}
	for _, em := range expectedMaps {
		if !containsMap(maps, em) {
			t.Fatalf("map %q not found", em)
		}
	}
}

func checkProbes(t *testing.T, b *elf.Module) {
	var expectedProbes = []string{
		"kprobe/dummy",
		"kretprobe/dummy",
	}

	var probes []*elf.Kprobe
	for p := range b.IterKprobes() {
		probes = append(probes, p)
	}
	if len(probes) != len(expectedProbes) {
		t.Fatalf("unexpected number of probes. Got %d, expected %d", len(probes), len(expectedProbes))
	}
	for _, ek := range expectedProbes {
		if !containsProbe(probes, ek) {
			t.Fatalf("probe %q not found", ek)
		}
	}
}

func checkUprobes(t *testing.T, b *elf.Module) {
	var expectedUprobes = []string{
		"uprobe/dummy",
		"uretprobe/dummy",
	}

	var uprobes []*elf.Uprobe
	for p := range b.IterUprobes() {
		uprobes = append(uprobes, p)
	}
	if len(uprobes) != len(expectedUprobes) {
		t.Fatalf("unexpected number of uprobes. Got %d, expected %d", len(uprobes), len(expectedUprobes))
	}
	for _, ek := range expectedUprobes {
		if !containsUprobe(uprobes, ek) {
			t.Fatalf("uprobe %q not found", ek)
		}
	}
}

func checkCgroupProgs(t *testing.T, b *elf.Module) {
	if kernelVersion < kernelVersion410 {
		t.Logf("kernel doesn't support cgroup-bpf. Skipping...")
		return
	}

	var expectedCgroupProgs = []string{
		"cgroup/skb",
		"cgroup/sock",
	}

	var cgroupProgs []*elf.CgroupProgram
	for p := range b.IterCgroupProgram() {
		cgroupProgs = append(cgroupProgs, p)
	}
	if len(cgroupProgs) != len(expectedCgroupProgs) {
		t.Fatalf("unexpected number of cgroup programs. Got %d, expected %v", len(cgroupProgs), len(expectedCgroupProgs))
	}
	for _, cp := range expectedCgroupProgs {
		if !containsCgroupProg(cgroupProgs, cp) {
			t.Fatalf("cgroup program %q not found", cp)
		}
	}
}

func checkXDPProgs(t *testing.T, b *elf.Module) {
	if kernelVersion < kernelVersion48 {
		t.Logf("kernel doesn't support XDP. Skipping...")
		t.Skip()
	}

	var expectedXDPProgs = []string{
		"xdp/prog1",
		"xdp/prog2",
	}

	var xdpProgs []*elf.XDPProgram
	for p := range b.IterXDPProgram() {
		xdpProgs = append(xdpProgs, p)
	}
	if len(xdpProgs) != len(expectedXDPProgs) {
		t.Fatalf("unexpected number of XDP programs. Got %d, expected %v", len(xdpProgs), len(expectedXDPProgs))
	}
}

func checkTracepointProgs(t *testing.T, b *elf.Module) {
	if kernelVersion < kernelVersion47 {
		t.Logf("kernel doesn't support bpf programs for tracepoints. Skipping...")
		return
	}

	var expectedTracepointProgs = []string{
		"tracepoint/raw_syscalls/sys_enter",
	}

	var tracepointProgs []*elf.TracepointProgram
	for p := range b.IterTracepointProgram() {
		tracepointProgs = append(tracepointProgs, p)
	}
	if len(tracepointProgs) != len(expectedTracepointProgs) {
		t.Fatalf("unexpected number of tracepoint programs. Got %d, expected %v", len(tracepointProgs), len(expectedTracepointProgs))
	}
	for _, p := range expectedTracepointProgs {
		if !containsTracepointProg(tracepointProgs, p) {
			t.Fatalf("tracepoint program %q not found", p)
		}
	}
}

func checkSocketFilters(t *testing.T, b *elf.Module) {
	var expectedSocketFilters = []string{
		"socket/dummy",
	}

	var socketFilters []*elf.SocketFilter
	for sf := range b.IterSocketFilter() {
		socketFilters = append(socketFilters, sf)
	}
	if len(socketFilters) != len(expectedSocketFilters) {
		t.Fatalf("unexpected number of socket filters. Got %d, expected %d", len(socketFilters), len(expectedSocketFilters))
	}
	for _, sf := range expectedSocketFilters {
		if !containsSocketFilter(socketFilters, sf) {
			t.Fatalf("socket filter %q not found", sf)
		}
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		t.Fatalf("unable to open a raw socket: %s", err)
	}
	defer syscall.Close(fd)

	socketFilter := b.SocketFilter("socket/dummy")
	if socketFilter == nil {
		t.Fatal("socket filter dummy not found")
	}

	if err := elf.AttachSocketFilter(socketFilter, fd); err != nil {
		t.Fatalf("failed trying to attach socket filter: %s", err)
	}

	if err := elf.DetachSocketFilter(socketFilter, fd); err != nil {
		t.Fatalf("failed trying to detach socket filter: %s", err)
	}
}

func checkPinConfig(t *testing.T, expectedPaths []string) {
	for _, p := range expectedPaths {
		if fi, err := os.Stat(p); os.IsNotExist(err) || !fi.Mode().IsRegular() {
			t.Fatalf("pinned object %q not found", p)
		}
	}
}

func checkPinConfigCleanup(t *testing.T, expectedPaths []string) {
	for _, p := range expectedPaths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("pinned object %q is not cleaned up", p)
		}
	}
}

func checkUpdateDeleteElement(t *testing.T, b *elf.Module) {
	mp := b.Map("dummy_hash")
	if mp == nil {
		t.Fatal("unable to find dummy_hash map")
	}

	key := 1000
	value := 1000
	if err := b.UpdateElement(mp, unsafe.Pointer(&key), unsafe.Pointer(&value), BPF_ANY); err != nil {
		t.Fatal("failed trying to update an element with BPF_ANY")
	}

	if err := b.UpdateElement(mp, unsafe.Pointer(&key), unsafe.Pointer(&value), BPF_NOEXIST); err == nil {
		t.Fatal("succeeded updating element with BPF_NOEXIST, but an element with the same key was added to the map before")
	}

	if err := b.UpdateElement(mp, unsafe.Pointer(&key), unsafe.Pointer(&value), BPF_EXIST); err != nil {
		t.Fatal("failed trying to update an element with BPF_EXIST while the key was added to the map before")
	}

	if err := b.DeleteElement(mp, unsafe.Pointer(&key)); err != nil {
		t.Fatal("failed to delete an element")
	}

	if err := b.UpdateElement(mp, unsafe.Pointer(&key), unsafe.Pointer(&value), BPF_EXIST); err == nil {
		t.Fatal("succeeded updating element with BPF_EXIST, but the element was deleted from the map before")
	}
}

func checkLookupElement(t *testing.T, b *elf.Module) {
	mp := b.Map("dummy_hash")
	if mp == nil {
		t.Fatal("unable to find dummy_hash map")
	}

	key := 2000
	value := 2000
	if err := b.UpdateElement(mp, unsafe.Pointer(&key), unsafe.Pointer(&value), BPF_ANY); err != nil {
		t.Fatal("failed trying to update an element with BPF_ANY")
	}

	var lvalue int
	if err := b.LookupElement(mp, unsafe.Pointer(&key), unsafe.Pointer(&lvalue)); err != nil {
		t.Fatal("failed trying to lookup an element previously added")
	}
	if value != lvalue {
		t.Fatalf("wrong value returned, expected %d, got %d", value, lvalue)
	}

	key = 3000
	if err := b.LookupElement(mp, unsafe.Pointer(&key), unsafe.Pointer(&lvalue)); err == nil {
		t.Fatalf("succeeded to find an element which wasn't added previously")
	}

	found := map[int]bool{2000: false}
	for i := 4000; i != 4010; i++ {
		key = i
		value = i
		if err := b.UpdateElement(mp, unsafe.Pointer(&key), unsafe.Pointer(&value), BPF_ANY); err != nil {
			t.Fatal("failed trying to update an element with BPF_ANY")
		}
		found[key] = false
	}

	key = 0
	nextKey := 0
	for {
		f, err := b.LookupNextElement(mp, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&lvalue))
		if err != nil {
			t.Fatalf("failed trying to lookup the next element: %s", err)
		}
		if !f {
			break
		}

		if nextKey != lvalue {
			t.Fatalf("key %d not corresponding to value %d", nextKey, lvalue)
		}

		if _, ok := found[nextKey]; !ok {
			t.Fatalf("key %d found", nextKey)
		}
		found[nextKey] = true

		key = nextKey
	}

	for key, f := range found {
		if !f {
			t.Fatalf("expected key %d not found", key)
		}
	}
}

func checkProgTestRun(t *testing.T, b *elf.Module) {
	if kernelVersion < kernelVersion412 {
		t.Logf("kernel doesn't support BPF_PROG_TEST_RUN. Skipping...")
		return
	}
	prog := b.CgroupProgram("cgroup/skb")
	if prog == nil {
		t.Fatal("unable to find prog")
	}
	// minimum amount of input data, but unused
	data := make([]byte, 14)
	returnValue, _, _, err := progtestrun.Run(prog.Fd(), 1, data, nil)
	if err != nil {
		t.Fatalf("bpf_prog_test_run failed: %v", err)
	}
	if returnValue != 1 {
		t.Fatalf("expected return value 1, got %d", returnValue)
	}
}

func TestModuleLoadELF(t *testing.T) {
	var err error
	kernelVersion, err = elf.CurrentKernelVersion()
	if err != nil {
		t.Fatalf("error getting current kernel version: %v", err)
	}

	dummyELF := "./tests/dummy.o"
	if kernelVersion > kernelVersion414 {
		dummyELF = "./tests/dummy-414.o"
	} else if kernelVersion > kernelVersion410 {
		dummyELF = "./tests/dummy-410.o"
	} else if kernelVersion > kernelVersion48 {
		dummyELF = "./tests/dummy-48.o"
	} else if kernelVersion > kernelVersion46 {
		dummyELF = "./tests/dummy-46.o"
	}

	var secParams = map[string]elf.SectionParams{
		"maps/dummy_array_custom": elf.SectionParams{
			PinPath: filepath.Join("gobpf-test", "testgroup1"),
		},
	}
	var closeOptions = map[string]elf.CloseOptions{
		"maps/dummy_array_custom": elf.CloseOptions{
			Unpin:   true,
			PinPath: filepath.Join("gobpf-test", "testgroup1"),
		},
	}

	if err := bpffs.Mount(); err != nil {
		t.Fatalf("error mounting bpf fs: %v", err)
	}

	b := elf.NewModule(dummyELF)
	if b == nil {
		t.Fatal("prog is nil")
	}
	if err := b.Load(secParams); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := b.CloseExt(closeOptions); err != nil {
			t.Fatal(err)
		}
		checkPinConfigCleanup(t, []string{"/sys/fs/bpf/gobpf-test/testgroup1"})
	}()

	checkMaps(t, b)
	checkProbes(t, b)
	checkUprobes(t, b)
	checkCgroupProgs(t, b)
	checkSocketFilters(t, b)
	checkTracepointProgs(t, b)
	checkXDPProgs(t, b)
	checkPinConfig(t, []string{"/sys/fs/bpf/gobpf-test/testgroup1"})
	checkUpdateDeleteElement(t, b)
	checkLookupElement(t, b)
	checkProgTestRun(t, b)
}
