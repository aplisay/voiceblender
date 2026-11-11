package sip

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

const testSRTPKey = "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz" // 30 bytes

func TestParseCrypto(t *testing.T) {
	ok := []struct {
		name, value, suite string
		tag                int
	}{
		{"80-bit tag", "1 AES_CM_128_HMAC_SHA1_80 inline:" + testSRTPKey, SRTPSuiteAES128SHA1_80, 1},
		{"32-bit tag", "2 AES_CM_128_HMAC_SHA1_32 inline:" + testSRTPKey, SRTPSuiteAES128SHA1_32, 2},
		{"lifetime is ignored", "1 AES_CM_128_HMAC_SHA1_80 inline:" + testSRTPKey + "|2^31", SRTPSuiteAES128SHA1_80, 1},
		{"suite in lower case", "7 aes_cm_128_hmac_sha1_80 inline:" + testSRTPKey, SRTPSuiteAES128SHA1_80, 7},
		{"extra spaces", "1  AES_CM_128_HMAC_SHA1_80   inline:" + testSRTPKey, SRTPSuiteAES128SHA1_80, 1},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseCrypto(tc.value)
			if err != nil {
				t.Fatalf("ParseCrypto: %v", err)
			}
			if c.Tag != tc.tag || c.Suite != tc.suite || len(c.Key) != 30 {
				t.Errorf("got tag %d suite %s key %d bytes", c.Tag, c.Suite, len(c.Key))
			}
		})
	}

	bad := []struct{ name, value string }{
		{"empty", ""},
		{"no key", "1 AES_CM_128_HMAC_SHA1_80"},
		{"bad tag", "x AES_CM_128_HMAC_SHA1_80 inline:" + testSRTPKey},
		{"unknown suite", "1 AES_256_CM_HMAC_SHA1_80 inline:" + testSRTPKey},
		{"not inline", "1 AES_CM_128_HMAC_SHA1_80 uri:" + testSRTPKey},
		{"MKI", "1 AES_CM_128_HMAC_SHA1_80 inline:" + testSRTPKey + "|2^20|1:4"},
		{"MKI without lifetime", "1 AES_CM_128_HMAC_SHA1_80 inline:" + testSRTPKey + "|1:4"},
		{"two keys", "1 AES_CM_128_HMAC_SHA1_80 inline:" + testSRTPKey + ";inline:" + testSRTPKey},
		{"session parameter", "1 AES_CM_128_HMAC_SHA1_80 inline:" + testSRTPKey + " UNENCRYPTED_SRTP"},
		{"bad base64", "1 AES_CM_128_HMAC_SHA1_80 inline:!!!!"},
		{"short key", "1 AES_CM_128_HMAC_SHA1_80 inline:" + base64.StdEncoding.EncodeToString(make([]byte, 16))},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCrypto(tc.value); err == nil {
				t.Errorf("ParseCrypto(%q) succeeded, want an error", tc.value)
			}
		})
	}
}

func TestCryptoAttr_StringRoundTrips(t *testing.T) {
	want := "3 AES_CM_128_HMAC_SHA1_32 inline:" + testSRTPKey
	c, err := ParseCrypto(want)
	if err != nil {
		t.Fatalf("ParseCrypto: %v", err)
	}
	if got := c.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// srtpPeer is the far end of an SRTP session, built on pion contexts directly
// so the tests do not check RTPSession against itself.
type srtpPeer struct {
	t    *testing.T
	conn *net.UDPConn
	key  CryptoAttr
	enc  *srtp.Context
	dec  *srtp.Context
}

func newSRTPPeer(t *testing.T, suite string) *srtpPeer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	key, err := newCryptoAttr(1, suite)
	if err != nil {
		t.Fatalf("newCryptoAttr: %v", err)
	}
	enc, err := newSRTPContext(key)
	if err != nil {
		t.Fatalf("peer encrypt context: %v", err)
	}
	return &srtpPeer{t: t, conn: conn, key: key, enc: enc}
}

func (p *srtpPeer) port() int { return p.conn.LocalAddr().(*net.UDPAddr).Port }

// warm sends junk until the session reads some, then leaves a 2 s read
// deadline. macOS now and then drops the first IPv4 datagram sent to a newly
// bound dual-stack socket, which would otherwise fail a test at random.
func (p *srtpPeer) warm(sess *RTPSession) {
	p.t.Helper()
	for i := 0; i < 40; i++ {
		p.sendRaw(sess, []byte{0})
		sess.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, err := sess.ReadRTP()
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			sess.SetReadDeadline(time.Now().Add(2 * time.Second))
			return
		}
	}
	p.t.Fatal("session socket never received a datagram")
}

// learn takes the session's a=crypto value as the key the peer decrypts with.
func (p *srtpPeer) learn(crypto string) {
	p.t.Helper()
	c, err := ParseCrypto(crypto)
	if err != nil {
		p.t.Fatalf("session crypto %q: %v", crypto, err)
	}
	if p.dec, err = newSRTPContext(c); err != nil {
		p.t.Fatalf("peer decrypt context: %v", err)
	}
}

func (p *srtpPeer) send(sess *RTPSession, seq uint16, payload []byte) {
	p.t.Helper()
	p.sendRaw(sess, p.protect(seq, payload))
}

func (p *srtpPeer) protect(seq uint16, payload []byte) []byte {
	p.t.Helper()
	pkt := rtp.Packet{
		Header:  rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: seq, Timestamp: uint32(seq) * 160, SSRC: 0x1234},
		Payload: payload,
	}
	raw, err := pkt.Marshal()
	if err != nil {
		p.t.Fatalf("marshal: %v", err)
	}
	out, err := p.enc.EncryptRTP(nil, raw, nil)
	if err != nil {
		p.t.Fatalf("peer encrypt: %v", err)
	}
	return out
}

func (p *srtpPeer) sendRaw(sess *RTPSession, wire []byte) {
	p.t.Helper()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sess.LocalPort()}
	if _, err := p.conn.WriteToUDP(wire, dst); err != nil {
		p.t.Fatalf("peer write: %v", err)
	}
}

// recv reads one packet the session sent and returns it as it was on the wire.
func (p *srtpPeer) recv() []byte {
	p.t.Helper()
	p.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := p.conn.ReadFromUDP(buf)
	if err != nil {
		p.t.Fatalf("peer read: %v", err)
	}
	return buf[:n]
}

func (p *srtpPeer) open(wire []byte) *rtp.Packet {
	p.t.Helper()
	plain, err := p.dec.DecryptRTP(nil, wire, nil)
	if err != nil {
		p.t.Fatalf("peer decrypt: %v", err)
	}
	pkt := &rtp.Packet{}
	if err := pkt.Unmarshal(plain); err != nil {
		p.t.Fatalf("peer unmarshal: %v", err)
	}
	return pkt
}

func newSecureTestSession(t *testing.T, peer *srtpPeer) *RTPSession {
	t.Helper()
	sess := newLoopbackRTPSession(t)
	crypto, err := sess.AnswerSRTP([]CryptoAttr{peer.key})
	if err != nil {
		t.Fatalf("AnswerSRTP: %v", err)
	}
	peer.learn(crypto)
	if err := sess.SetRemote("127.0.0.1", peer.port()); err != nil {
		t.Fatalf("SetRemote: %v", err)
	}
	peer.warm(sess)
	return sess
}

func newLoopbackRTPSession(t *testing.T) *RTPSession {
	t.Helper()
	sess, err := NewRTPSession()
	if err != nil {
		t.Fatalf("NewRTPSession: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func TestRTPSession_PlainByDefault(t *testing.T) {
	sess := newLoopbackRTPSession(t)
	if sess.Secure() {
		t.Error("a new session reports Secure")
	}
	if got := sess.LocalCrypto(); got != "" {
		t.Errorf("LocalCrypto() = %q on a plain session", got)
	}
}

// Both suites, both directions, against pion contexts keyed from the SDP
// values alone.
func TestSRTP_AnswerSide_BothSuites(t *testing.T) {
	for _, suite := range []string{SRTPSuiteAES128SHA1_80, SRTPSuiteAES128SHA1_32} {
		t.Run(suite, func(t *testing.T) {
			peer := newSRTPPeer(t, suite)
			peer.key.Tag = 4
			sess := newSecureTestSession(t, peer)

			if !sess.Secure() {
				t.Fatal("session is not Secure after AnswerSRTP")
			}
			local, err := ParseCrypto(sess.LocalCrypto())
			if err != nil {
				t.Fatalf("LocalCrypto: %v", err)
			}
			if local.Tag != 4 || local.Suite != suite {
				t.Errorf("answer crypto = tag %d %s, want the offered tag 4 and %s", local.Tag, local.Suite, suite)
			}
			if bytes.Equal(local.Key, peer.key.Key) {
				t.Error("answer reuses the offerer's key")
			}

			payload := bytes.Repeat([]byte{0x55}, 160)
			peer.send(sess, 10, payload)
			got, err := sess.ReadRTP()
			if err != nil {
				t.Fatalf("ReadRTP: %v", err)
			}
			if got.SequenceNumber != 10 || !bytes.Equal(got.Payload, payload) {
				t.Errorf("decrypted seq %d, payload match %v", got.SequenceNumber, bytes.Equal(got.Payload, payload))
			}

			out := &rtp.Packet{
				Header:  rtp.Header{Version: 2, SequenceNumber: 7, Timestamp: 1120, SSRC: 0xBEEF},
				Payload: payload,
			}
			if err := sess.WriteRTP(out); err != nil {
				t.Fatalf("WriteRTP: %v", err)
			}
			wire := peer.recv()
			tagLen := 10
			if suite == SRTPSuiteAES128SHA1_32 {
				tagLen = 4
			}
			if want := 12 + len(payload) + tagLen; len(wire) != want {
				t.Errorf("wire packet is %d bytes, want %d", len(wire), want)
			}
			if bytes.Contains(wire, payload[:16]) {
				t.Error("payload is on the wire in the clear")
			}
			if back := peer.open(wire); back.SequenceNumber != 7 || !bytes.Equal(back.Payload, payload) {
				t.Error("peer did not recover the packet the session sent")
			}

			// WriteRTPBuf and SendKeepalive share the encrypting send path.
			out.SequenceNumber = 8
			if _, err := sess.WriteRTPBuf(out, nil); err != nil {
				t.Fatalf("WriteRTPBuf: %v", err)
			}
			if back := peer.open(peer.recv()); back.SequenceNumber != 8 {
				t.Errorf("WriteRTPBuf packet seq = %d, want 8", back.SequenceNumber)
			}
			sess.SendKeepalive(0, 1)
			if back := peer.open(peer.recv()); len(back.Payload) != 160 {
				t.Errorf("keepalive payload = %d bytes, want 160", len(back.Payload))
			}
		})
	}
}

func TestSRTP_OfferSide(t *testing.T) {
	sess := newLoopbackRTPSession(t)
	offer, err := sess.OfferSRTP()
	if err != nil {
		t.Fatalf("OfferSRTP: %v", err)
	}
	if !strings.HasPrefix(offer, "1 "+SRTPSuiteAES128SHA1_80+" inline:") {
		t.Errorf("offer = %q, want one AES_CM_128_HMAC_SHA1_80 line on tag 1", offer)
	}
	if !sess.Secure() {
		t.Error("session is not Secure after OfferSRTP")
	}
	if again, _ := sess.OfferSRTP(); again != offer {
		t.Error("a second OfferSRTP changed the key")
	}

	peer := newSRTPPeer(t, SRTPSuiteAES128SHA1_80)
	peer.learn(offer)
	// The answer's tag is not compared with the offer's.
	peer.key.Tag = 9
	if err := sess.AcceptSRTPAnswer([]CryptoAttr{peer.key}); err != nil {
		t.Fatalf("AcceptSRTPAnswer: %v", err)
	}
	if sess.LocalCrypto() != offer {
		t.Error("accepting the answer changed the local key")
	}
	peer.warm(sess)
	peer.send(sess, 1, []byte{1, 2, 3, 4})
	if _, err := sess.ReadRTP(); err != nil {
		t.Fatalf("ReadRTP after answer: %v", err)
	}
}

func TestSRTP_AcceptAnswerRefusals(t *testing.T) {
	plain := newLoopbackRTPSession(t)
	if err := plain.AcceptSRTPAnswer(nil); err == nil {
		t.Error("AcceptSRTPAnswer succeeded with no offer outstanding")
	}

	sess := newLoopbackRTPSession(t)
	offer, _ := sess.OfferSRTP()
	other, _ := newCryptoAttr(1, SRTPSuiteAES128SHA1_32)
	for name, answered := range map[string][]CryptoAttr{
		"plain answer":    nil,
		"different suite": {other},
	} {
		if err := sess.AcceptSRTPAnswer(answered); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !sess.Secure() || sess.LocalCrypto() != offer {
		t.Error("a refused answer changed the session")
	}
	if _, err := sess.AnswerSRTP(nil); err == nil {
		t.Error("AnswerSRTP succeeded on an offer with no crypto line")
	}
}

func TestSRTP_RejectsWhatDoesNotAuthenticate(t *testing.T) {
	peer := newSRTPPeer(t, SRTPSuiteAES128SHA1_80)
	sess := newSecureTestSession(t, peer)
	latched := sess.RemoteAddr().String()

	intruder, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer intruder.Close()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sess.LocalPort()}

	plain, _ := (&rtp.Packet{
		Header:  rtp.Header{Version: 2, SequenceNumber: 1, SSRC: 0x1234},
		Payload: bytes.Repeat([]byte{0xFF}, 160),
	}).Marshal()
	tampered := peer.protect(2, bytes.Repeat([]byte{0x11}, 160))
	tampered[20] ^= 0x01

	for name, wire := range map[string][]byte{"plain RTP": plain, "tampered SRTP": tampered} {
		if _, err := intruder.WriteToUDP(wire, dst); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := sess.ReadRTP(); !errors.Is(err, ErrSRTP) {
			t.Errorf("%s: err = %v, want ErrSRTP", name, err)
		}
	}
	if got := sess.RemoteAddr().String(); got != latched {
		t.Errorf("remote address moved to %s on packets that failed authentication", got)
	}

	good := peer.protect(3, []byte{1, 2, 3, 4})
	peer.sendRaw(sess, good)
	if _, err := sess.ReadRTP(); err != nil {
		t.Fatalf("first copy: %v", err)
	}
	peer.sendRaw(sess, good)
	if _, err := sess.ReadRTP(); !errors.Is(err, ErrSRTP) {
		t.Errorf("replayed packet: err = %v, want ErrSRTP", err)
	}
}

func TestSRTP_NoRemoteKeyYet(t *testing.T) {
	sess := newLoopbackRTPSession(t)
	if _, err := sess.OfferSRTP(); err != nil {
		t.Fatalf("OfferSRTP: %v", err)
	}
	peer := newSRTPPeer(t, SRTPSuiteAES128SHA1_80)
	peer.warm(sess)
	peer.send(sess, 1, []byte{1, 2, 3, 4})
	if _, err := sess.ReadRTP(); !errors.Is(err, ErrSRTP) {
		t.Errorf("err = %v, want ErrSRTP before the answer's key is known", err)
	}
}

// A re-offer that repeats the keys must keep both contexts. A rebuilt context
// starts its rollover counter at zero, and the two ends then disagree on every
// packet after the sequence number has wrapped.
func TestSRTP_SameKeysKeepRolloverCounter(t *testing.T) {
	peer := newSRTPPeer(t, SRTPSuiteAES128SHA1_80)
	sess := newSecureTestSession(t, peer)
	before := sess.LocalCrypto()

	exchange := func(seq uint16) {
		t.Helper()
		peer.send(sess, seq, []byte{byte(seq), 1, 2, 3})
		if _, err := sess.ReadRTP(); err != nil {
			t.Fatalf("read seq %d: %v", seq, err)
		}
		out := &rtp.Packet{Header: rtp.Header{Version: 2, SequenceNumber: seq, SSRC: 0xBEEF}, Payload: []byte{byte(seq)}}
		if err := sess.WriteRTP(out); err != nil {
			t.Fatalf("write seq %d: %v", seq, err)
		}
		if got := peer.open(peer.recv()); got.SequenceNumber != seq {
			t.Fatalf("peer read seq %d, want %d", got.SequenceNumber, seq)
		}
	}

	for _, seq := range []uint16{65533, 65534, 65535, 0, 1} {
		exchange(seq)
	}

	// The peer re-offers with the same key first on the list or not.
	fresh, _ := newCryptoAttr(2, SRTPSuiteAES128SHA1_80)
	after, err := sess.AnswerSRTP([]CryptoAttr{fresh, peer.key})
	if err != nil {
		t.Fatalf("AnswerSRTP on re-offer: %v", err)
	}
	if after != before {
		t.Errorf("re-offer with the same key changed our crypto line:\n was %s\n now %s", before, after)
	}
	// And we re-offer, getting the same key back.
	if err := sess.AcceptSRTPAnswer([]CryptoAttr{peer.key}); err != nil {
		t.Fatalf("AcceptSRTPAnswer on re-offer: %v", err)
	}

	for _, seq := range []uint16{2, 3} {
		exchange(seq)
	}
}

func TestSRTP_NewRemoteKeyRekeysReceiveOnly(t *testing.T) {
	peer := newSRTPPeer(t, SRTPSuiteAES128SHA1_80)
	sess := newSecureTestSession(t, peer)
	before := sess.LocalCrypto()
	peer.send(sess, 1, []byte{1, 2, 3, 4})
	if _, err := sess.ReadRTP(); err != nil {
		t.Fatalf("ReadRTP: %v", err)
	}

	rekeyed := newSRTPPeer(t, SRTPSuiteAES128SHA1_80)
	after, err := sess.AnswerSRTP([]CryptoAttr{rekeyed.key})
	if err != nil {
		t.Fatalf("AnswerSRTP: %v", err)
	}
	if after != before {
		t.Error("a new remote key changed our own key")
	}
	rekeyed.send(sess, 2, []byte{5, 6, 7, 8})
	if _, err := sess.ReadRTP(); err != nil {
		t.Fatalf("ReadRTP with the new key: %v", err)
	}
	peer.send(sess, 3, []byte{9, 9, 9, 9})
	if _, err := sess.ReadRTP(); !errors.Is(err, ErrSRTP) {
		t.Errorf("old key still accepted: err = %v", err)
	}
}

func TestSRTP_SuiteChangeMakesNewLocalKey(t *testing.T) {
	peer := newSRTPPeer(t, SRTPSuiteAES128SHA1_80)
	sess := newSecureTestSession(t, peer)
	before, _ := ParseCrypto(sess.LocalCrypto())

	other := newSRTPPeer(t, SRTPSuiteAES128SHA1_32)
	crypto, err := sess.AnswerSRTP([]CryptoAttr{other.key})
	if err != nil {
		t.Fatalf("AnswerSRTP: %v", err)
	}
	after, _ := ParseCrypto(crypto)
	if after.Suite != SRTPSuiteAES128SHA1_32 || bytes.Equal(after.Key, before.Key) {
		t.Errorf("suite change: suite %s, key reused %v", after.Suite, bytes.Equal(after.Key, before.Key))
	}
}

// Received SRTCP is authenticated, then dropped like plain RTCP: nothing on a
// SIP leg reads the reports.
func TestSRTP_MuxedSRTCP(t *testing.T) {
	peer := newSRTPPeer(t, SRTPSuiteAES128SHA1_80)
	sess := newSecureTestSession(t, peer)

	rr, err := (&rtcp.ReceiverReport{SSRC: 0x1234}).Marshal()
	if err != nil {
		t.Fatalf("marshal RR: %v", err)
	}
	wire, err := peer.enc.EncryptRTCP(nil, rr, nil)
	if err != nil {
		t.Fatalf("EncryptRTCP: %v", err)
	}
	peer.sendRaw(sess, wire)
	if _, err := sess.ReadRTP(); !errors.Is(err, ErrNotRTP) {
		t.Errorf("authentic SRTCP: err = %v, want ErrNotRTP", err)
	}

	bad := append([]byte(nil), wire...)
	bad[len(bad)-1] ^= 0x01
	peer.sendRaw(sess, bad)
	if _, err := sess.ReadRTP(); !errors.Is(err, ErrSRTP) {
		t.Errorf("tampered SRTCP: err = %v, want ErrSRTP", err)
	}
	peer.sendRaw(sess, rr)
	if _, err := sess.ReadRTP(); !errors.Is(err, ErrSRTP) {
		t.Errorf("plain RTCP on an SRTP session: err = %v, want ErrSRTP", err)
	}
}
