package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TestValidateListenAddressRefusesNonLoopback proves the provider can
// never be configured to serve off-host: only loopback IPs and
// localhost pass, everything else is a startup refusal.
func TestValidateListenAddressRefusesNonLoopback(t *testing.T) {
	accepted := []string{
		"127.0.0.1:0",
		"127.0.0.1:9100",
		"localhost:9100",
		"[::1]:9100",
	}
	for _, addr := range accepted {
		if err := validateListenAddress(addr); err != nil {
			t.Errorf("validateListenAddress(%q) = %v, want loopback accepted", addr, err)
		}
	}
	refused := []string{
		"0.0.0.0:9100",      // all interfaces
		":9100",             // all interfaces, empty host
		"[::]:9100",         // all interfaces, IPv6
		"192.168.1.10:9100", // private but routable
		"10.0.0.1:9100",
		"example.com:9100", // host name that is not localhost
		"127.0.0.1",        // missing port
		"not-an-address",
		"127.0.0.1:notaport",
	}
	for _, addr := range refused {
		if err := validateListenAddress(addr); err == nil {
			t.Errorf("validateListenAddress(%q) accepted a non-loopback listen address", addr)
		}
	}
}

// TestVerifyLoopbackListener proves the bound address is checked after
// the fact, so a bind that resolved somewhere unexpected is refused.
func TestVerifyLoopbackListener(t *testing.T) {
	loopback, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer loopback.Close()
	if err := verifyLoopbackListener(loopback); err != nil {
		t.Fatalf("loopback listener refused: %v", err)
	}

	// A listener whose address is not loopback is refused. Binding a
	// routable address may not be possible in every environment, so the
	// check is exercised through a synthetic address.
	synthetic := &addrListener{addr: &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 9100}}
	if err := verifyLoopbackListener(synthetic); err == nil {
		t.Fatal("a non-loopback bound address must be refused")
	}
}

type addrListener struct {
	addr net.Addr
}

func (l *addrListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *addrListener) Close() error              { return nil }
func (l *addrListener) Addr() net.Addr            { return l.addr }

// TestBoundedListenerRefusesAtCeiling proves a connection at the
// ceiling is closed immediately — an explicit refusal, not queued work —
// and that releasing a slot admits the next connection.
func TestBoundedListenerRefusesAtCeiling(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	ln := &boundedListener{Listener: inner, slots: make(chan struct{}, 1)}

	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	dial := func() net.Conn {
		t.Helper()
		conn, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}

	first := dial()
	defer first.Close()
	var held net.Conn
	select {
	case held = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the first connection was not accepted")
	}

	second := dial()
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := second.Read(buf); err == nil {
		t.Fatal("a connection at the ceiling stayed open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("a connection at the ceiling was neither refused nor closed")
	}

	// Releasing the slot admits the next connection.
	held.Close()
	third := dial()
	defer third.Close()
	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("a connection after the slot was released was not accepted")
	}
}

// TestRefusalMessageNamesTheBoundary keeps the operator-facing error
// honest about why the address was refused.
func TestRefusalMessageNamesTheBoundary(t *testing.T) {
	err := validateListenAddress("0.0.0.0:9100")
	if err == nil {
		t.Fatal("0.0.0.0 must be refused")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("refusal does not name the loopback requirement: %v", err)
	}
}
