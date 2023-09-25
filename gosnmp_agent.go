// Copyright 2023 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"net"
	"strconv"
)

// BindAgent
// TODO: Write docs

func (x *GoSNMP) BindAgent() error {
	x.isAgent = true
	return x.bindAgent("")
}

// ConnectIPv4 forces an IPv4-only connection
func (x *GoSNMP) BindAgentIPv4() error {
	x.isAgent = true
	return x.bindAgent("4")
}

// ConnectIPv6 forces an IPv6-only connection
func (x *GoSNMP) BindAgentIPv6() error {
	x.isAgent = true
	return x.bindAgent("6")
}

// Performs the real socket opening network operation. This can be used to do a
// reconnect (needed for TCP)
func (x *GoSNMP) netBind() error {
	var err error
	var localAddr net.Addr
	addr := net.JoinHostPort(x.Target, strconv.Itoa(int(x.Port)))

	switch x.Transport {
	case "udp", "udp4", "udp6":
		if localAddr, err = net.ResolveUDPAddr(x.Transport, x.LocalAddr); err != nil {
			return err
		}
		if addr4 := localAddr.(*net.UDPAddr).IP.To4(); addr4 != nil {
			x.Transport = "udp4"
		}
		if x.UseUnconnectedUDPSocket {
			x.uaddr, err = net.ResolveUDPAddr(x.Transport, addr)
			if err != nil {
				return err
			}
			x.Conn, err = net.ListenUDP(x.Transport, localAddr.(*net.UDPAddr))
			return err
		}
	case "tcp", "tcp4", "tcp6":
		if localAddr, err = net.ResolveTCPAddr(x.Transport, x.LocalAddr); err != nil {
			return err
		}
		if addr4 := localAddr.(*net.TCPAddr).IP.To4(); addr4 != nil {
			x.Transport = "tcp4"
		}
	}
	dialer := net.Dialer{Timeout: x.Timeout, LocalAddr: localAddr, Control: x.Control}
	x.Conn, err = dialer.DialContext(x.Context, x.Transport, addr)
	return err
}

func (x *GoSNMP) bindAgent(networkSuffix string) error {
	err := x.validateParameters()
	if err != nil {
		return err
	}

	x.Transport += networkSuffix
	if err = x.netBind(); err != nil {
		return fmt.Errorf("error binding agent socket: %w", err)
	}

	if x.random == 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32)) // returns a uniform random value in [0, 2147483647].
		if err != nil {
			return fmt.Errorf("error occurred while generating random: %w", err)
		}
		x.random = uint32(n.Uint64())
	}
	// http://tools.ietf.org/html/rfc3412#section-6 - msgID only uses the first 31 bits
	// msgID INTEGER (0..2147483647)
	x.msgID = x.random

	// RequestID is Integer32 from SNMPV2-SMI and uses all 32 bits
	x.requestID = x.random

	x.rxBuf = new([rxBufSize]byte)

	return nil
}
