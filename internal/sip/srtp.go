package sip

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pion/srtp/v3"
)

// ErrSRTP is returned by ReadRTP when a packet on an SRTP session fails
// authentication or is a replay. Callers should continue reading, and must not
// count the packet as media.
var ErrSRTP = errors.New("srtp: packet rejected")

// SDES crypto suites (RFC 4568 §6.2).
const (
	SRTPSuiteAES128SHA1_80 = "AES_CM_128_HMAC_SHA1_80"
	SRTPSuiteAES128SHA1_32 = "AES_CM_128_HMAC_SHA1_32"
)

var srtpProfiles = map[string]srtp.ProtectionProfile{
	SRTPSuiteAES128SHA1_80: srtp.ProtectionProfileAes128CmHmacSha1_80,
	SRTPSuiteAES128SHA1_32: srtp.ProtectionProfileAes128CmHmacSha1_32,
}

// srtpReplayWindow is the replay window RFC 3711 §3.3.2 recommends.
const srtpReplayWindow = 64

// CryptoAttr is one a=crypto line (RFC 4568) that this server can use.
type CryptoAttr struct {
	Tag   int
	Suite string
	Key   []byte // master key followed by master salt
}

// String renders the attribute value, the text after "a=crypto:".
func (c CryptoAttr) String() string {
	return fmt.Sprintf("%d %s inline:%s", c.Tag, c.Suite, base64.StdEncoding.EncodeToString(c.Key))
}

func (c CryptoAttr) sameKey(o CryptoAttr) bool {
	return c.Suite == o.Suite && bytes.Equal(c.Key, o.Key)
}

// ParseCrypto parses an a=crypto attribute value. It fails for a line this
// server cannot use: an unknown suite, an MKI, more than one key, or any
// session parameter, which RFC 4568 §6.3 says to refuse when not supported. A
// key lifetime is accepted and ignored.
func ParseCrypto(value string) (CryptoAttr, error) {
	fields := strings.Fields(value)
	if len(fields) < 3 {
		return CryptoAttr{}, fmt.Errorf("crypto: malformed attribute")
	}
	if len(fields) > 3 {
		return CryptoAttr{}, fmt.Errorf("crypto: session parameters not supported")
	}
	tag, err := strconv.Atoi(fields[0])
	if err != nil || tag < 0 {
		return CryptoAttr{}, fmt.Errorf("crypto: bad tag %q", fields[0])
	}
	suite := strings.ToUpper(fields[1])
	profile, ok := srtpProfiles[suite]
	if !ok {
		return CryptoAttr{}, fmt.Errorf("crypto: unsupported suite %q", fields[1])
	}
	if strings.Contains(fields[2], ";") {
		return CryptoAttr{}, fmt.Errorf("crypto: multiple keys not supported")
	}
	method, info, ok := strings.Cut(fields[2], ":")
	if !ok || !strings.EqualFold(method, "inline") {
		return CryptoAttr{}, fmt.Errorf("crypto: unsupported key method")
	}
	parts := strings.Split(info, "|")
	for _, p := range parts[1:] {
		if strings.Contains(p, ":") {
			return CryptoAttr{}, fmt.Errorf("crypto: MKI not supported")
		}
	}
	key, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return CryptoAttr{}, fmt.Errorf("crypto: bad key encoding")
	}
	if want := srtpKeyingLen(profile); len(key) != want {
		return CryptoAttr{}, fmt.Errorf("crypto: key is %d bytes, want %d", len(key), want)
	}
	return CryptoAttr{Tag: tag, Suite: suite, Key: key}, nil
}

func srtpKeyingLen(profile srtp.ProtectionProfile) int {
	keyLen, _ := profile.KeyLen()
	saltLen, _ := profile.SaltLen()
	return keyLen + saltLen
}

func newCryptoAttr(tag int, suite string) (CryptoAttr, error) {
	profile, ok := srtpProfiles[suite]
	if !ok {
		return CryptoAttr{}, fmt.Errorf("crypto: unsupported suite %q", suite)
	}
	key := make([]byte, srtpKeyingLen(profile))
	if _, err := rand.Read(key); err != nil {
		return CryptoAttr{}, fmt.Errorf("crypto: generate key: %w", err)
	}
	return CryptoAttr{Tag: tag, Suite: suite, Key: key}, nil
}

func newSRTPContext(c CryptoAttr) (*srtp.Context, error) {
	profile := srtpProfiles[c.Suite]
	keyLen, _ := profile.KeyLen()
	return srtp.CreateContext(c.Key[:keyLen], c.Key[keyLen:], profile,
		srtp.SRTPReplayProtection(srtpReplayWindow),
		srtp.SRTCPReplayProtection(srtpReplayWindow))
}

// srtpState holds an RTP session's SDES keys and SRTP contexts. The zero value
// is plain RTP. Once a local key exists the session never goes back to plain.
//
// A context is rebuilt only when its key changes: it carries the rollover
// counter, and a fresh one under the same key would lose sync with the peer
// after the first sequence-number wrap.
type srtpState struct {
	on atomic.Bool

	mu     sync.Mutex
	local  CryptoAttr
	remote CryptoAttr
	enc    *srtp.Context
	dec    *srtp.Context
	encBuf []byte
}

// setLocal makes sure a local key exists for suite and records the tag our next
// SDP carries. Caller holds mu.
func (c *srtpState) setLocal(tag int, suite string) error {
	if c.enc != nil && c.local.Suite == suite {
		c.local.Tag = tag
		return nil
	}
	attr, err := newCryptoAttr(tag, suite)
	if err != nil {
		return err
	}
	enc, err := newSRTPContext(attr)
	if err != nil {
		return err
	}
	c.local, c.enc = attr, enc
	c.on.Store(true)
	return nil
}

// setRemote installs the peer's key. Caller holds mu.
func (c *srtpState) setRemote(attr CryptoAttr) error {
	if c.dec != nil && c.remote.sameKey(attr) {
		return nil
	}
	dec, err := newSRTPContext(attr)
	if err != nil {
		return err
	}
	c.remote, c.dec = attr, dec
	return nil
}

// Secure reports whether the session carries SRTP. It turns true on the first
// OfferSRTP or AnswerSRTP and stays true for the life of the session.
func (s *RTPSession) Secure() bool { return s.crypto.on.Load() }

// LocalCrypto returns the a=crypto value our SDP carries for this session, or
// "" for a plain RTP session.
func (s *RTPSession) LocalCrypto() string {
	if !s.Secure() {
		return ""
	}
	s.crypto.mu.Lock()
	defer s.crypto.mu.Unlock()
	return s.crypto.local.String()
}

// OfferSRTP returns the a=crypto value to offer, creating the local key on
// first use. A session that already negotiated SRTP offers the same key again.
func (s *RTPSession) OfferSRTP() (string, error) {
	c := &s.crypto
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enc == nil {
		if err := c.setLocal(1, SRTPSuiteAES128SHA1_80); err != nil {
			return "", err
		}
	}
	return c.local.String(), nil
}

// AnswerSRTP picks a crypto line from a peer's offer, installs its key and
// returns the a=crypto value our answer must carry. A line that repeats the
// key already in use is preferred, so a re-offer keeps both contexts.
func (s *RTPSession) AnswerSRTP(offered []CryptoAttr) (string, error) {
	if len(offered) == 0 {
		return "", fmt.Errorf("srtp: offer carries no usable crypto line")
	}
	c := &s.crypto
	c.mu.Lock()
	defer c.mu.Unlock()
	pick := offered[0]
	for _, o := range offered {
		if c.dec != nil && c.remote.sameKey(o) {
			pick = o
			break
		}
	}
	if err := c.setRemote(pick); err != nil {
		return "", err
	}
	if err := c.setLocal(pick.Tag, pick.Suite); err != nil {
		return "", err
	}
	return c.local.String(), nil
}

// AcceptSRTPAnswer installs the key from a peer's answer to our offer. It
// leaves the session untouched and fails when the answer has no crypto line
// for the suite we offered, which includes a plain RTP answer.
func (s *RTPSession) AcceptSRTPAnswer(answered []CryptoAttr) error {
	c := &s.crypto
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enc == nil {
		return fmt.Errorf("srtp: no offer outstanding")
	}
	// We only ever offer one line, so the suite identifies it. The tag is not
	// compared: some stacks renumber it in the answer.
	for _, a := range answered {
		if a.Suite == c.local.Suite {
			return c.setRemote(a)
		}
	}
	return fmt.Errorf("srtp: answer carries no crypto line for %s", c.local.Suite)
}

// unprotect authenticates and decrypts an SRTP packet in place and returns the
// RTP packet's length.
func (c *srtpState) unprotect(buf []byte, n int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dec == nil {
		return 0, fmt.Errorf("no remote key yet")
	}
	out, err := c.dec.DecryptRTP(buf[:0], buf[:n], nil)
	if err != nil {
		return 0, err
	}
	return len(out), nil
}

// checkRTCP authenticates an SRTCP packet. The engine has no use for the
// report itself; an authentic one only shows the peer is alive.
func (c *srtpState) checkRTCP(buf []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dec == nil {
		return fmt.Errorf("no remote key yet")
	}
	_, err := c.dec.DecryptRTCP(nil, buf, nil)
	return err
}

// protectAndSend encrypts a marshalled RTP packet and writes it to addr.
func (c *srtpState) protectAndSend(conn *net.UDPConn, data []byte, addr *net.UDPAddr) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.enc.EncryptRTP(c.encBuf[:0], data, nil)
	if err != nil {
		return fmt.Errorf("srtp encrypt: %w", err)
	}
	c.encBuf = out
	_, err = conn.WriteToUDP(out, addr)
	return err
}
