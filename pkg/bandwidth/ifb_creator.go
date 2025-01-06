// Copyright 2018 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bandwidth

import (
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/plugins/pkg/ip"
)

const LatencyInMillis = 25

func CreateIfb(ifbDeviceName string, mtu int) error {
	// do not set TxQLen > 0 nor TxQLen == -1 until issues have been fixed with numrxqueues / numtxqueues across interfaces
	// which needs to get set on IFB devices via upstream library: see hint https://github.com/containernetworking/plugins/pull/1097
	err := netlink.LinkAdd(&netlink.Ifb{
		LinkAttrs: netlink.LinkAttrs{
			Name:   ifbDeviceName,
			Flags:  net.FlagUp,
			MTU:    mtu,
			TxQLen: 0,
		},
	})
	if err != nil {
		return fmt.Errorf("adding link: %s", err)
	}

	return nil
}

func TeardownIfb(deviceName string) error {
	_, err := ip.DelLinkByNameAddr(deviceName)
	if err != nil && err == ip.ErrLinkNotFound {
		return nil
	}
	return err
}

func CreateIngressQdisc(rateInBits, burstInBits uint64, hostDeviceName string) error {
	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		return fmt.Errorf("get host device: %s", err)
	}
	return createTBF(rateInBits, burstInBits, hostDevice.Attrs().Index)
}

func CreateEgressQdisc(rateInBits, burstInBits uint64, hostDeviceName string, ifbDeviceName string) error {
	ifbDevice, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		return fmt.Errorf("get ifb device: %s", err)
	}
	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		return fmt.Errorf("get host device: %s", err)
	}

	// add qdisc clsact on host device
	clsact := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: hostDevice.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0), // ffff:
			Parent:    netlink.HANDLE_CLSACT,
		},
	}

	err = netlink.QdiscAdd(clsact)
	if err != nil {
		return fmt.Errorf("create clsact qdisc: %s", err)
	}

	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: hostDevice.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		ClassId:    netlink.MakeHandle(1, 1),
		RedirIndex: ifbDevice.Attrs().Index,
		Actions:    []netlink.Action{netlink.NewMirredAction(ifbDevice.Attrs().Index)},
	}
	err = netlink.FilterAdd(filter)
	if err != nil {
		return fmt.Errorf("add egress filter: %s", err)
	}

	// throttle traffic on ifb device
	err = createTBF(rateInBits, burstInBits, ifbDevice.Attrs().Index)
	if err != nil {
		return fmt.Errorf("create ifb qdisc: %s", err)
	}
	return nil
}

func createTBF(rateInBits, burstInBits uint64, linkIndex int) error {
	// Equivalent to
	// tc qdisc add dev link root tbf
	//		rate netConf.BandwidthLimits.Rate
	//		burst netConf.BandwidthLimits.Burst
	if rateInBits <= 0 {
		return fmt.Errorf("invalid rate: %d", rateInBits)
	}
	if burstInBits <= 0 {
		return fmt.Errorf("invalid burst: %d", burstInBits)
	}
	rateInBytes := rateInBits / 8
	burstInBytes := burstInBits / 8
	bufferInBytes := Buffer(rateInBytes, uint32(burstInBytes))
	latency := LatencyInUsec(LatencyInMillis)
	limitInBytes := Limit(rateInBytes, latency, uint32(burstInBytes))

	qdisc := &netlink.Tbf{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkIndex,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		Limit:  limitInBytes,
		Rate:   rateInBytes,
		Buffer: bufferInBytes,
	}
	err := netlink.QdiscAdd(qdisc)
	if err != nil {
		return fmt.Errorf("create qdisc: %s", err)
	}
	return nil
}

func time2Tick(time uint32) uint32 {
	return uint32(float64(time) * netlink.TickInUsec())
}

func Buffer(rate uint64, burst uint32) uint32 {
	return time2Tick(uint32(float64(burst) * float64(netlink.TIME_UNITS_PER_SEC) / float64(rate)))
}

func Limit(rate uint64, latency float64, buffer uint32) uint32 {
	return uint32(float64(rate)*latency/float64(netlink.TIME_UNITS_PER_SEC)) + buffer
}

func LatencyInUsec(LatencyInMillis float64) float64 {
	return float64(netlink.TIME_UNITS_PER_SEC) * (LatencyInMillis / 1000.0)
}
