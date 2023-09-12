// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package netmon

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"testing"

	ktu "github.com/kata-containers/kata-containers/src/runtime/pkg/katatestutils"
	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	pbTypes "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/vcmock"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/utils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	testSandboxID          = "777-77-77777777"
	testContainerID        = "42"
	testRuntimePath        = "/foo/bar/test-runtime"
	testWrongNetlinkFamily = -1
	testIfaceName          = "test_eth0"
	testMTU                = 12345
	testHwAddr             = "02:00:ca:fe:00:48"
	testIPAddress          = "192.168.0.15"
	testIPAddressWithMask  = "192.168.0.15/32"
	testIP6Address         = "2001:db8:1::242:ac11:2"
	testIP6AddressWithMask = "2001:db8:1::/64"
	testScope              = 1
	testTxQLen             = -1
	testIfaceIndex         = 5
	testFamily_v4          = 2
	testFamily_v6          = 10
)

func skipUnlessRoot(t *testing.T) {
	tc := ktu.NewTestConstraint(false)

	if tc.NotValid(ktu.NeedRoot()) {
		t.Skip("Test disabled as requires root user")
	}
}

func TestNewNetmon(t *testing.T) {
	skipUnlessRoot(t)

	expected := &netmon{
		sandboxID: testSandboxID,
	}
	sandbox := &vcmock.Sandbox{
		MockID: testSandboxID,
		MockContainers: []*vcmock.Container{
			{MockID: testContainerID},
		},
	}
	got, err := newNetmon(sandbox)
	assert.Nil(t, err)
	assert.True(t, reflect.DeepEqual(expected.sandboxID, got.sandboxID),
		"Got %+v\nExpected %+v", got.sandboxID, expected.sandboxID)
}

func TestNewNetmonErrorWrongFamilyType(t *testing.T) {
	// Override netlinkFamily
	savedNetlinkFamily := netlinkFamily
	netlinkFamily = testWrongNetlinkFamily
	defer func() {
		netlinkFamily = savedNetlinkFamily
	}()

	n, err := newNetmon(&vc.Sandbox{})
	assert.NotNil(t, err)
	assert.Nil(t, n)
}

func TestCleanup(t *testing.T) {
	skipUnlessRoot(t)
	handler, err := netlink.NewHandle(netlinkFamily)
	assert.Nil(t, err)

	n := &netmon{
		linkDoneCh: make(chan struct{}),
		rtDoneCh:   make(chan struct{}),
		netHandler: handler,
	}

	n.cleanup()
	_, ok := (<-n.linkDoneCh)
	assert.False(t, ok)
	_, ok = (<-n.rtDoneCh)
	assert.False(t, ok)
}

func TestLogger(t *testing.T) {
	fields := logrus.Fields{
		"name":    netmonName,
		"pid":     os.Getpid(),
		"source":  "netmon",
		"sandbox": testSandboxID,
	}

	expected := netmonLog.WithFields(fields)

	n := &netmon{
		sandboxID: testSandboxID,
	}

	got := n.logger()
	assert.True(t, reflect.DeepEqual(*expected, *got),
		"Got %+v\nExpected %+v", *got, *expected)
}

func TestConvertInterface(t *testing.T) {
	hwAddr, err := net.ParseMAC(testHwAddr)
	assert.Nil(t, err)

	addrs := []netlink.Addr{
		{
			IPNet: &net.IPNet{
				IP: net.ParseIP(testIPAddress),
			},
		},
		{
			IPNet: &net.IPNet{
				IP: net.ParseIP(testIP6Address),
			},
		},
	}

	linkAttrs := &netlink.LinkAttrs{
		Name:         testIfaceName,
		MTU:          testMTU,
		HardwareAddr: hwAddr,
	}

	linkType := "link_type_test"

	expected := pbTypes.Interface{
		Device: testIfaceName,
		Name:   testIfaceName,
		Mtu:    uint64(testMTU),
		HwAddr: testHwAddr,
		IPAddresses: []*pbTypes.IPAddress{
			{
				Family:  pbTypes.IPFamily_v4,
				Address: testIPAddress,
				Mask:    "0",
			},
			{
				Family:  pbTypes.IPFamily_v6,
				Address: testIP6Address,
				Mask:    "0",
			},
		},
	}

	got := convertInterface(linkAttrs, linkType, addrs)

	assert.True(t, reflect.DeepEqual(expected, got),
		"Got %+v\nExpected %+v", got, expected)
}

func TestConvertRoutes(t *testing.T) {
	ip, ipNet, err := net.ParseCIDR(testIPAddressWithMask)
	assert.Nil(t, err)
	assert.NotNil(t, ipNet)

	_, ip6Net, err := net.ParseCIDR(testIP6AddressWithMask)
	assert.Nil(t, err)
	assert.NotNil(t, ipNet)

	routes := []netlink.Route{
		{
			Dst:       ipNet,
			Src:       ip,
			Gw:        ip,
			LinkIndex: -1,
			Scope:     testScope,
			Family:    testFamily_v4,
		},
		{
			Dst:       ip6Net,
			Src:       nil,
			Gw:        nil,
			LinkIndex: -1,
			Scope:     testScope,
			Family:    testFamily_v6,
		},
	}

	expected := []pbTypes.Route{
		{
			Dest:    testIPAddressWithMask,
			Gateway: testIPAddress,
			Source:  testIPAddress,
			Scope:   uint32(testScope),
			Family:  utils.ConvertAddressFamily((int32)(testFamily_v4)),
		},
		{
			Dest:    testIP6AddressWithMask,
			Gateway: "",
			Source:  "",
			Scope:   uint32(testScope),
			Family:  utils.ConvertAddressFamily((int32)(testFamily_v6)),
		},
	}

	got := convertRoutes(routes)
	assert.True(t, reflect.DeepEqual(expected, got),
		"Got %+v\nExpected %+v", got, expected)
}

type testTeardownNetwork func()

func testSetupNetwork(t *testing.T) testTeardownNetwork {
	skipUnlessRoot(t)

	// new temporary namespace so we don't pollute the host
	// lock thread since the namespace is thread local
	runtime.LockOSThread()
	var err error
	ns, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns", ns)
	}

	return func() {
		ns.Close()
		runtime.UnlockOSThread()
	}
}

func testCreateDummyNetwork(t *testing.T, handler *netlink.Handle) (int, pbTypes.Interface) {
	hwAddr, err := net.ParseMAC(testHwAddr)
	assert.Nil(t, err)

	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			MTU:          testMTU,
			TxQLen:       testTxQLen,
			Name:         testIfaceName,
			HardwareAddr: hwAddr,
		},
	}

	err = handler.LinkAdd(link)
	assert.Nil(t, err)
	err = handler.LinkSetUp(link)
	assert.Nil(t, err)

	attrs := link.Attrs()
	assert.NotNil(t, attrs)

	addrs, err := handler.AddrList(link, netlinkFamily)
	assert.Nil(t, err)

	var ipAddrs []*pbTypes.IPAddress

	// Scan addresses for ipv6 link local address which is automatically assigned
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}

		netMask, _ := addr.Mask.Size()

		ipAddr := &pbTypes.IPAddress{
			Address: addr.IP.String(),
			Mask:    fmt.Sprintf("%d", netMask),
		}

		if addr.IP.To4() != nil {
			ipAddr.Family = netlink.FAMILY_V4
		} else {
			ipAddr.Family = netlink.FAMILY_V6
		}

		ipAddrs = append(ipAddrs, ipAddr)
	}

	iface := pbTypes.Interface{
		Device:      testIfaceName,
		Name:        testIfaceName,
		Mtu:         uint64(testMTU),
		HwAddr:      testHwAddr,
		IPAddresses: ipAddrs,
	}

	return attrs.Index, iface
}

func TestScanNetwork(t *testing.T) {
	tearDownNetworkCb := testSetupNetwork(t)
	defer tearDownNetworkCb()

	handler, err := netlink.NewHandle(netlinkFamily)
	assert.Nil(t, err)
	assert.NotNil(t, handler)
	defer handler.Delete()

	idx, expected := testCreateDummyNetwork(t, handler)

	n := &netmon{
		netIfaces:  make(map[int]pbTypes.Interface),
		netHandler: handler,
	}

	err = n.scanNetwork()
	assert.Nil(t, err)
	assert.True(t, reflect.DeepEqual(expected, n.netIfaces[idx]),
		"Got %+v\nExpected %+v", n.netIfaces[idx], expected)
}

func TestActionsCLI(t *testing.T) {
	trueBinPath, err := exec.LookPath("true")
	assert.Nil(t, err)
	assert.NotEmpty(t, trueBinPath)

	n := &netmon{
		sandboxID: testSandboxID,
	}
	ctx := context.Background()
	// Test addInterfaceCLI
	err = n.addInterface(ctx, pbTypes.Interface{})
	assert.Nil(t, err)

	// Test delInterfaceCLI
	err = n.removeInterface(ctx, pbTypes.Interface{})
	assert.Nil(t, err)

	// Test updateRoutesCLI
	err = n.updateRoutes(ctx)
	assert.Nil(t, err)

	tearDownNetworkCb := testSetupNetwork(t)
	defer tearDownNetworkCb()

	handler, err := netlink.NewHandle(netlinkFamily)
	assert.Nil(t, err)
	assert.NotNil(t, handler)
	defer handler.Close()

	n.netHandler = handler

	// Test updateRoutes
	err = n.updateRoutes(ctx)
	assert.Nil(t, err)

	// Test handleRTMDelRoute
	err = n.handleRTMDelRoute(ctx, netlink.RouteUpdate{})
	assert.Nil(t, err)
}

func TestHandleRTMNewAddr(t *testing.T) {
	n := &netmon{}
	ctx := context.Background()
	err := n.handleRTMNewAddr(ctx, netlink.LinkUpdate{})
	assert.Nil(t, err)
}

func TestHandleRTMDelAddr(t *testing.T) {
	n := &netmon{}
	ctx := context.Background()
	err := n.handleRTMDelAddr(ctx, netlink.LinkUpdate{})
	assert.Nil(t, err)
}

func TestHandleRTMNewLink(t *testing.T) {
	n := &netmon{}
	ev := netlink.LinkUpdate{
		Link: &netlink.Dummy{},
	}
	ctx := context.Background()
	// LinkAttrs is nil
	err := n.handleRTMNewLink(ctx, ev)
	assert.Nil(t, err)

	// Link name contains "kata" suffix
	ev = netlink.LinkUpdate{
		Link: &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "foo_kata",
			},
		},
	}
	err = n.handleRTMNewLink(ctx, ev)
	assert.Nil(t, err)

	// Interface already exist in list
	n.netIfaces = make(map[int]pbTypes.Interface)
	n.netIfaces[testIfaceIndex] = pbTypes.Interface{}
	ev = netlink.LinkUpdate{
		Link: &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "foo0",
			},
		},
	}
	ev.Index = testIfaceIndex
	err = n.handleRTMNewLink(ctx, ev)
	assert.Nil(t, err)

	// Flags are not up and running
	n.netIfaces = make(map[int]pbTypes.Interface)
	ev = netlink.LinkUpdate{
		Link: &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "foo0",
			},
		},
	}
	ev.Index = testIfaceIndex
	err = n.handleRTMNewLink(ctx, ev)
	assert.Nil(t, err)

	// Invalid link
	n.netIfaces = make(map[int]pbTypes.Interface)
	ev = netlink.LinkUpdate{
		Link: &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "foo0",
			},
		},
	}
	ev.Index = testIfaceIndex
	ev.Flags = unix.IFF_UP | unix.IFF_RUNNING
	handler, err := netlink.NewHandle(netlinkFamily)
	assert.Nil(t, err)
	assert.NotNil(t, handler)
	defer handler.Close()
	n.netHandler = handler
	err = n.handleRTMNewLink(ctx, ev)
	assert.NotNil(t, err)
}

func TestHandleRTMDelLink(t *testing.T) {
	n := &netmon{}
	ev := netlink.LinkUpdate{
		Link: &netlink.Dummy{},
	}
	ctx := context.Background()
	// LinkAttrs is nil
	err := n.handleRTMDelLink(ctx, ev)
	assert.Nil(t, err)

	// Link name contains "kata" suffix
	ev = netlink.LinkUpdate{
		Link: &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "foo_kata",
			},
		},
	}
	err = n.handleRTMDelLink(ctx, ev)
	assert.Nil(t, err)

	// Interface does not exist in list
	n.netIfaces = make(map[int]pbTypes.Interface)
	ev = netlink.LinkUpdate{
		Link: &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "foo0",
			},
		},
	}
	ev.Index = testIfaceIndex
	err = n.handleRTMDelLink(ctx, ev)
	assert.Nil(t, err)
}

func TestHandleRTMNewRouteIfaceNotFound(t *testing.T) {
	n := &netmon{
		netIfaces: make(map[int]pbTypes.Interface),
	}
	ctx := context.Background()
	err := n.handleRTMNewRoute(ctx, netlink.RouteUpdate{})
	assert.Nil(t, err)
}

func TestHandleLinkEvent(t *testing.T) {
	n := &netmon{}
	ev := netlink.LinkUpdate{}
	ctx := context.Background()
	// Unknown event
	err := n.handleLinkEvent(ctx, ev)
	assert.Nil(t, err)

	// DONE event
	ev.Header.Type = unix.NLMSG_DONE
	err = n.handleLinkEvent(ctx, ev)
	assert.Nil(t, err)

	// ERROR event
	ev.Header.Type = unix.NLMSG_ERROR
	err = n.handleLinkEvent(ctx, ev)
	assert.NotNil(t, err)

	// NEWADDR event
	ev.Header.Type = unix.RTM_NEWADDR
	err = n.handleLinkEvent(ctx, ev)
	assert.Nil(t, err)

	// DELADDR event
	ev.Header.Type = unix.RTM_DELADDR
	err = n.handleLinkEvent(ctx, ev)
	assert.Nil(t, err)

	// NEWLINK event
	ev.Header.Type = unix.RTM_NEWLINK
	ev.Link = &netlink.Dummy{}
	err = n.handleLinkEvent(ctx, ev)
	assert.Nil(t, err)

	// DELLINK event
	ev.Header.Type = unix.RTM_DELLINK
	ev.Link = &netlink.Dummy{}
	err = n.handleLinkEvent(ctx, ev)
	assert.Nil(t, err)
}

func TestHandleRouteEvent(t *testing.T) {
	n := &netmon{}
	ev := netlink.RouteUpdate{}
	ctx := context.Background()
	// Unknown event
	err := n.handleRouteEvent(ctx, ev)
	assert.Nil(t, err)

	// RTM_NEWROUTE event
	ev.Type = unix.RTM_NEWROUTE
	err = n.handleRouteEvent(ctx, ev)
	assert.Nil(t, err)

	trueBinPath, err := exec.LookPath("true")
	assert.Nil(t, err)
	assert.NotEmpty(t, trueBinPath)

	tearDownNetworkCb := testSetupNetwork(t)
	defer tearDownNetworkCb()

	handler, err := netlink.NewHandle(netlinkFamily)
	assert.Nil(t, err)
	assert.NotNil(t, handler)
	defer handler.Close()

	n.netHandler = handler

	// RTM_DELROUTE event
	ev.Type = unix.RTM_DELROUTE
	err = n.handleRouteEvent(ctx, ev)
	assert.Nil(t, err)
}
