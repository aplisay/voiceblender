//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/VoiceBlender/voiceblender/internal/events"
	sipmod "github.com/VoiceBlender/voiceblender/internal/sip"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type srtpStreamView struct {
	ID      string `json:"id"`
	Primary bool   `json:"primary"`
	SRTP    bool   `json:"srtp"`
}

func legStreams(t *testing.T, inst *testInstance, legID string) []srtpStreamView {
	t.Helper()
	resp := httpGet(t, fmt.Sprintf("%s/v1/legs/%s/streams", inst.baseURL(), legID))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list streams: status %d", resp.StatusCode)
	}
	var streams []srtpStreamView
	decodeJSON(t, resp, &streams)
	return streams
}

func assertLegSRTP(t *testing.T, inst *testInstance, legID string, want bool) {
	t.Helper()
	streams := legStreams(t, inst, legID)
	if len(streams) == 0 {
		t.Fatalf("[%s] leg %s has no streams", inst.name, legID)
	}
	for _, s := range streams {
		if s.SRTP != want {
			t.Fatalf("[%s] leg %s stream %s: srtp = %v, want %v", inst.name, legID, s.ID, s.SRTP, want)
		}
	}
}

// establishSRTPCall is establishCall with SRTP required on the outbound leg.
func establishSRTPCall(t *testing.T, instA, instB *testInstance) (outboundID, inboundID string) {
	t.Helper()
	createResp := httpPost(t, instA.baseURL()+"/v1/legs", map[string]interface{}{
		"type":   "sip",
		"uri":    fmt.Sprintf("sip:test@127.0.0.1:%d", instB.sipPort),
		"codecs": []string{"PCMU"},
		"srtp":   "required",
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create leg: unexpected status %d", createResp.StatusCode)
	}
	var outbound legView
	decodeJSON(t, createResp, &outbound)

	inbound := waitForInboundLeg(t, instB.baseURL(), 5*time.Second)
	answerResp := httpPost(t, fmt.Sprintf("%s/v1/legs/%s/answer", instB.baseURL(), inbound.ID), nil)
	if answerResp.StatusCode != http.StatusAccepted {
		t.Fatalf("answer: unexpected status %d", answerResp.StatusCode)
	}
	answerResp.Body.Close()

	waitForLegState(t, instA.baseURL(), outbound.ID, "connected", 5*time.Second)
	waitForLegState(t, instB.baseURL(), inbound.ID, "connected", 5*time.Second)
	return outbound.ID, inbound.ID
}

func waitForHeld(t *testing.T, inst *testInstance, legID string, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp := httpGet(t, fmt.Sprintf("%s/v1/legs/%s", inst.baseURL(), legID))
		var v legView
		decodeJSON(t, resp, &v)
		if v.Held == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("[%s] leg %s: held did not become %v", inst.name, legID, want)
}

func playTone(t *testing.T, inst *testInstance, legID string) {
	t.Helper()
	resp := httpPost(t, fmt.Sprintf("%s/v1/legs/%s/play", inst.baseURL(), legID),
		map[string]interface{}{"tone": "us_dial", "repeat": -1, "volume": 0})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("play tone: status %d, body=%s", resp.StatusCode, body)
	}
	resp.Body.Close()
}

// expectAudio fails unless the leg decodes non-silent audio from now on.
func expectAudio(t *testing.T, inst *testInstance, legID, what string) {
	t.Helper()
	sl := sipLegOf(t, inst, legID)
	tap := &countingTap{}
	sl.SetInTap(tap)
	defer sl.ClearInTap()
	if !waitNonSilence(t, tap, 5*time.Second) {
		t.Fatalf("%s: no audio decoded on %s leg %s (non-zero bytes=%d)", what, inst.name, legID, tap.count())
	}
}

func srtpOffer(port int, direction string, crypto ...string) []byte {
	lines := []string{
		"v=0",
		"o=raw 1 1 IN IP4 127.0.0.1",
		"s=-",
		"c=IN IP4 127.0.0.1",
		"t=0 0",
	}
	if len(crypto) == 0 {
		lines = append(lines, fmt.Sprintf("m=audio %d RTP/AVP 0 101", port))
	} else {
		lines = append(lines, fmt.Sprintf("m=audio %d RTP/SAVP 0 101", port))
	}
	lines = append(lines,
		"a=rtpmap:0 PCMU/8000",
		"a=rtpmap:101 telephone-event/8000",
		"a=fmtp:101 0-15",
		"a="+direction,
		"a=rtcp-mux",
	)
	for _, c := range crypto {
		lines = append(lines, "a=crypto:"+c)
	}
	return []byte(strings.Join(append(lines, ""), "\r\n"))
}

func sdpAttr(t *testing.T, body []byte, name string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(string(body), "\r\n") {
		if v, ok := strings.CutPrefix(line, "a="+name+":"); ok {
			out = append(out, v)
		}
	}
	return out
}

// srtpWire is a media endpoint that speaks SRTP with pion contexts built only
// from the keys in the SDP, so it checks what the engine puts on the wire.
type srtpWire struct {
	t    *testing.T
	conn *net.UDPConn
	enc  *srtp.Context
	dec  *srtp.Context
	dst  *net.UDPAddr
	seq  uint16
	ssrc uint32
}

func newSRTPWire(t *testing.T) *srtpWire {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen media: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &srtpWire{t: t, conn: conn, ssrc: 0x51515151}
}

func (w *srtpWire) port() int { return w.conn.LocalAddr().(*net.UDPAddr).Port }

func srtpContextFor(t *testing.T, crypto string) *srtp.Context {
	t.Helper()
	c, err := sipmod.ParseCrypto(crypto)
	if err != nil {
		t.Fatalf("crypto line %q: %v", crypto, err)
	}
	profile := srtp.ProtectionProfileAes128CmHmacSha1_80
	if c.Suite == sipmod.SRTPSuiteAES128SHA1_32 {
		profile = srtp.ProtectionProfileAes128CmHmacSha1_32
	}
	ctx, err := srtp.CreateContext(c.Key[:16], c.Key[16:], profile)
	if err != nil {
		t.Fatalf("srtp context: %v", err)
	}
	return ctx
}

// keys sets the key this endpoint sends with and the key it expects from the
// engine. An unchanged line keeps its context, as a real endpoint would.
func (w *srtpWire) keys(ours, theirs string, enginePort int) {
	w.t.Helper()
	if w.enc == nil {
		w.enc = srtpContextFor(w.t, ours)
	}
	w.dec = srtpContextFor(w.t, theirs)
	w.dst = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: enginePort}
}

// send writes n packets of a loud PCMU pattern, 20 ms apart.
func (w *srtpWire) send(n int) {
	w.t.Helper()
	payload := make([]byte, 160)
	for i := range payload {
		payload[i] = byte(0x10 + i%0x40)
	}
	for i := 0; i < n; i++ {
		w.seq++
		raw, err := (&rtp.Packet{
			Header:  rtp.Header{Version: 2, PayloadType: 0, SequenceNumber: w.seq, Timestamp: uint32(w.seq) * 160, SSRC: w.ssrc},
			Payload: payload,
		}).Marshal()
		if err != nil {
			w.t.Fatalf("marshal: %v", err)
		}
		out, err := w.enc.EncryptRTP(nil, raw, nil)
		if err != nil {
			w.t.Fatalf("encrypt: %v", err)
		}
		if _, err := w.conn.WriteToUDP(out, w.dst); err != nil {
			w.t.Fatalf("write media: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// drain discards what the engine has already sent. The engine sends a packet
// every 20 ms, so the deadline is fixed rather than renewed per packet.
func (w *srtpWire) drain() {
	buf := make([]byte, 1500)
	w.conn.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	for {
		if _, _, err := w.conn.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

// expectSRTP reads engine packets until one decrypts with the negotiated key,
// and returns it with its size on the wire.
func (w *srtpWire) expectSRTP(what string) (*rtp.Packet, int) {
	w.t.Helper()
	buf := make([]byte, 1500)
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		w.conn.SetReadDeadline(deadline)
		n, _, err := w.conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		plain, err := w.dec.DecryptRTP(nil, buf[:n], nil)
		if err != nil {
			lastErr = err
			continue
		}
		pkt := &rtp.Packet{}
		if err := pkt.Unmarshal(plain); err != nil {
			lastErr = err
			continue
		}
		// The first packets after an answer are a keepalive burst on SSRC 0.
		if pkt.SSRC == 0 {
			continue
		}
		return pkt, n
	}
	w.t.Fatalf("%s: no engine packet decrypted with the negotiated key (last error: %v)", what, lastErr)
	return nil, 0
}

// inDialog sends an in-dialog request from the calling side and returns the
// final response, ACKing a 2xx to an INVITE.
func inDialog(t *testing.T, ctx context.Context, dialog *sipgo.DialogClientSession, method sip.RequestMethod, body []byte, hdrs ...sip.Header) *sip.Response {
	t.Helper()
	target := dialog.InviteResponse.Contact().Address
	req := sip.NewRequest(method, target)
	req.AppendHeader(dialog.InviteRequest.Contact())
	for _, h := range hdrs {
		req.AppendHeader(h)
	}
	if len(body) > 0 {
		req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		req.SetBody(body)
	}
	res, err := dialog.Do(ctx, req)
	if err != nil {
		t.Fatalf("in-dialog %s: %v", method, err)
	}
	if method == sip.INVITE && res.IsSuccess() {
		if err := dialog.WriteRequest(sip.NewRequest(sip.ACK, target)); err != nil {
			t.Fatalf("ACK re-INVITE: %v", err)
		}
	}
	return res
}

// ---------------------------------------------------------------------------
// Two engines
// ---------------------------------------------------------------------------

// TestSRTP_TwoLegsExchangeAudio places a call that requires SRTP between two
// instances and checks audio both ways, then across hold and resume from each
// side. A hold is a re-INVITE, so it also covers renegotiation on a secure leg.
func TestSRTP_TwoLegsExchangeAudio(t *testing.T) {
	instA := newTestInstance(t, "srtp-a")
	instB := newTestInstance(t, "srtp-b")
	outboundID, inboundID := establishSRTPCall(t, instA, instB)

	assertLegSRTP(t, instA, outboundID, true)
	assertLegSRTP(t, instB, inboundID, true)

	playTone(t, instA, outboundID)
	playTone(t, instB, inboundID)
	expectAudio(t, instB, inboundID, "A to B")
	expectAudio(t, instA, outboundID, "B to A")

	// The legs' held flag is polled rather than the hold events awaited: the
	// second cycle would match the events the first one left behind.
	holdAndResume := func(holder *testInstance, holderLeg string, other *testInstance, otherLeg string) {
		t.Helper()
		resp := httpPost(t, fmt.Sprintf("%s/v1/legs/%s/hold", holder.baseURL(), holderLeg), nil)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("hold: status %d", resp.StatusCode)
		}
		resp.Body.Close()
		waitForHeld(t, holder, holderLeg, true)
		waitForHeld(t, other, otherLeg, true)

		resp = httpDelete(t, fmt.Sprintf("%s/v1/legs/%s/hold", holder.baseURL(), holderLeg))
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("unhold: status %d", resp.StatusCode)
		}
		resp.Body.Close()
		waitForHeld(t, holder, holderLeg, false)
		waitForHeld(t, other, otherLeg, false)
	}

	holdAndResume(instA, outboundID, instB, inboundID)
	assertLegSRTP(t, instA, outboundID, true)
	assertLegSRTP(t, instB, inboundID, true)
	expectAudio(t, instB, inboundID, "A to B after A held and resumed")
	expectAudio(t, instA, outboundID, "B to A after A held and resumed")

	holdAndResume(instB, inboundID, instA, outboundID)
	assertLegSRTP(t, instA, outboundID, true)
	assertLegSRTP(t, instB, inboundID, true)
	expectAudio(t, instB, inboundID, "A to B after B held and resumed")
	expectAudio(t, instA, outboundID, "B to A after B held and resumed")

	hangup(t, instA, outboundID)
	expectDisconnect(t, instB, inboundID)
}

// TestSRTP_PlainCallUnchanged pins the default: with no srtp field the call is
// plain RTP at both ends.
func TestSRTP_PlainCallUnchanged(t *testing.T) {
	instA := newTestInstance(t, "plain-a")
	instB := newTestInstance(t, "plain-b")
	outboundID, inboundID := establishCall(t, instA, instB)

	assertLegSRTP(t, instA, outboundID, false)
	assertLegSRTP(t, instB, inboundID, false)

	playTone(t, instA, outboundID)
	expectAudio(t, instB, inboundID, "A to B")
	hangup(t, instA, outboundID)
}

// TestSRTP_EarlyMedia checks the 183 answer is keyed before early audio, and
// that the 200 OK keeps it.
func TestSRTP_EarlyMedia(t *testing.T) {
	instA := newTestInstance(t, "srtp-em-a")
	instB := newTestInstance(t, "srtp-em-b")

	createResp := httpPost(t, instA.baseURL()+"/v1/legs", map[string]interface{}{
		"type":   "sip",
		"uri":    fmt.Sprintf("sip:test@127.0.0.1:%d", instB.sipPort),
		"codecs": []string{"PCMU"},
		"srtp":   "required",
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create leg: unexpected status %d", createResp.StatusCode)
	}
	var outbound legView
	decodeJSON(t, createResp, &outbound)
	inbound := waitForInboundLeg(t, instB.baseURL(), 5*time.Second)

	emResp := httpPost(t, fmt.Sprintf("%s/v1/legs/%s/early-media", instB.baseURL(), inbound.ID), nil)
	if emResp.StatusCode != http.StatusAccepted {
		t.Fatalf("early-media: unexpected status %d", emResp.StatusCode)
	}
	emResp.Body.Close()
	waitForLegState(t, instA.baseURL(), outbound.ID, "early_media", 5*time.Second)
	assertLegSRTP(t, instA, outbound.ID, true)

	playTone(t, instB, inbound.ID)
	expectAudio(t, instA, outbound.ID, "early media B to A")

	answerResp := httpPost(t, fmt.Sprintf("%s/v1/legs/%s/answer", instB.baseURL(), inbound.ID), nil)
	answerResp.Body.Close()
	waitForLegState(t, instA.baseURL(), outbound.ID, "connected", 5*time.Second)
	assertLegSRTP(t, instA, outbound.ID, true)
	assertLegSRTP(t, instB, inbound.ID, true)
	expectAudio(t, instA, outbound.ID, "B to A after answer")
	hangup(t, instA, outbound.ID)
}

// TestSRTP_AddedStreamIsSRTP adds a second audio stream to a secure call. The
// new section must be offered and answered on SRTP with its own key.
func TestSRTP_AddedStreamIsSRTP(t *testing.T) {
	instA := multiStreamInstance(t, "srtp-ms-a")
	instB := multiStreamInstance(t, "srtp-ms-b")
	outboundID, inboundID := establishSRTPCall(t, instA, instB)

	addResp := httpPost(t, fmt.Sprintf("%s/v1/legs/%s/streams", instA.baseURL(), outboundID), map[string]interface{}{
		"direction": "sendonly",
		"content":   "alt",
	})
	if addResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(addResp.Body)
		t.Fatalf("add stream: unexpected status %d: %s", addResp.StatusCode, b)
	}
	addResp.Body.Close()

	for _, side := range []struct {
		inst *testInstance
		id   string
	}{{instA, outboundID}, {instB, inboundID}} {
		if n := len(legStreams(t, side.inst, side.id)); n != 2 {
			t.Fatalf("[%s] leg has %d streams, want 2", side.inst.name, n)
		}
		assertLegSRTP(t, side.inst, side.id, true)
	}
	hangup(t, instA, outboundID)
}

// ---------------------------------------------------------------------------
// A scripted peer
// ---------------------------------------------------------------------------

// TestSRTP_InboundOffer_OnTheWire calls the engine from a scripted SIP client
// and checks the answer, the packets on the wire in both directions, and what
// later offers on the same dialog do.
func TestSRTP_InboundOffer_OnTheWire(t *testing.T) {
	inst := newTestInstance(t, "srtp-wire")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const (
		key32 = "1 AES_CM_128_HMAC_SHA1_32 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR"
		key80 = "2 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
	)
	wire := newSRTPWire(t)
	recipient := sip.Uri{Scheme: "sip", User: "500", Host: "127.0.0.1", Port: inst.sipPort}
	dialog, inbound := answerInboundCall(t, ctx, inst, recipient, srtpOffer(wire.port(), "sendrecv", key32, key80))

	answer, err := sipmod.ParseSDP(dialog.InviteResponse.Body())
	if err != nil {
		t.Fatalf("parse answer: %v\n%s", err, dialog.InviteResponse.Body())
	}
	if !strings.Contains(string(dialog.InviteResponse.Body()), " RTP/SAVP 0 101\r\n") {
		t.Fatalf("answer is not on RTP/SAVP:\n%s", dialog.InviteResponse.Body())
	}
	lines := sdpAttr(t, dialog.InviteResponse.Body(), "crypto")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "1 AES_CM_128_HMAC_SHA1_32 inline:") {
		t.Fatalf("answer crypto lines = %q, want one line taking the first offered suite and its tag", lines)
	}
	engineKey := lines[0]
	if strings.Contains(engineKey, "PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR") {
		t.Fatal("answer repeats the offerer's key")
	}
	if err := dialog.Ack(ctx); err != nil {
		t.Fatalf("ACK: %v", err)
	}
	waitForLegState(t, inst.baseURL(), inbound.ID, "connected", 5*time.Second)
	assertLegSRTP(t, inst, inbound.ID, true)

	wire.keys(key32, engineKey, answer.RemotePort)

	// Peer to engine: only a correct decrypt yields this audio.
	tap := &countingTap{}
	sl := sipLegOf(t, inst, inbound.ID)
	sl.SetInTap(tap)
	wire.send(25)
	if !waitNonSilence(t, tap, 3*time.Second) {
		t.Fatalf("engine decoded no audio from the peer's SRTP (non-zero bytes=%d)", tap.count())
	}
	sl.ClearInTap()

	// Engine to peer: packets decrypt with the key from the answer, and carry
	// the short tag of the negotiated suite.
	pkt, size := wire.expectSRTP("after answer")
	if pkt.PayloadType != 0 || len(pkt.Payload) != 160 {
		t.Errorf("engine packet: pt %d, %d payload bytes, want PCMU with 160", pkt.PayloadType, len(pkt.Payload))
	}
	if want := 12 + 160 + 4; size != want {
		t.Errorf("engine packet is %d bytes on the wire, want %d (4 byte tag)", size, want)
	}

	// A plain re-offer is refused and changes nothing.
	res := inDialog(t, ctx, dialog, sip.INVITE, srtpOffer(wire.port(), "sendrecv"))
	if res.StatusCode != sip.StatusNotAcceptableHere {
		t.Fatalf("plain re-INVITE on an SRTP leg answered %d %s, want 488", res.StatusCode, res.Reason)
	}
	res = inDialog(t, ctx, dialog, sip.UPDATE, srtpOffer(wire.port(), "sendrecv"))
	if res.StatusCode != sip.StatusNotAcceptableHere {
		t.Fatalf("plain UPDATE on an SRTP leg answered %d %s, want 488", res.StatusCode, res.Reason)
	}
	waitForLegState(t, inst.baseURL(), inbound.ID, "connected", 2*time.Second)
	assertLegSRTP(t, inst, inbound.ID, true)
	wire.drain()
	wire.expectSRTP("after the refused offers")

	// A refresh repeats the offer. The answer must repeat our key.
	res = inDialog(t, ctx, dialog, sip.INVITE, srtpOffer(wire.port(), "sendrecv", key32, key80),
		sip.NewHeader("Session-Expires", "1800;refresher=uac"), sip.NewHeader("Supported", "timer"))
	if res.StatusCode != sip.StatusOK {
		t.Fatalf("refresh re-INVITE answered %d %s", res.StatusCode, res.Reason)
	}
	if got := sdpAttr(t, res.Body(), "crypto"); len(got) != 1 || got[0] != engineKey {
		t.Fatalf("refresh answer crypto = %q, want the key already in use %q", got, engineKey)
	}
	if se := res.GetHeader("Session-Expires"); se == nil {
		t.Error("refresh answer lacks Session-Expires")
	}

	// Hold, then resume.
	res = inDialog(t, ctx, dialog, sip.INVITE, srtpOffer(wire.port(), "sendonly", key32, key80))
	if res.StatusCode != sip.StatusOK {
		t.Fatalf("hold re-INVITE answered %d %s", res.StatusCode, res.Reason)
	}
	if body := string(res.Body()); !strings.Contains(body, " RTP/SAVP ") || !strings.Contains(body, "a=recvonly") {
		t.Fatalf("hold answer:\n%s", body)
	}
	if got := sdpAttr(t, res.Body(), "crypto"); len(got) != 1 || got[0] != engineKey {
		t.Fatalf("hold answer crypto = %q, want %q", got, engineKey)
	}
	inst.collector.waitForMatch(t, events.LegHold, forLeg(inbound.ID), 3*time.Second)

	res = inDialog(t, ctx, dialog, sip.INVITE, srtpOffer(wire.port(), "sendrecv", key32, key80))
	if res.StatusCode != sip.StatusOK {
		t.Fatalf("resume re-INVITE answered %d %s", res.StatusCode, res.Reason)
	}
	inst.collector.waitForMatch(t, events.LegUnhold, forLeg(inbound.ID), 3*time.Second)

	// Media still flows both ways on the contexts from before the hold.
	tap = &countingTap{}
	sl.SetInTap(tap)
	wire.send(25)
	if !waitNonSilence(t, tap, 3*time.Second) {
		t.Fatalf("no audio from the peer after resume (non-zero bytes=%d)", tap.count())
	}
	sl.ClearInTap()
	wire.drain()
	wire.expectSRTP("after resume")

	if err := dialog.Bye(ctx); err != nil {
		t.Fatalf("BYE: %v", err)
	}
	expectDisconnect(t, inst, inbound.ID)
}

// TestSRTP_InboundOffer_Unusable checks an offer whose audio needs SRTP the
// engine cannot provide is refused with 488 and not answered as plain RTP.
func TestSRTP_InboundOffer_Unusable(t *testing.T) {
	tests := []struct {
		name  string
		offer []byte
	}{
		{"unknown suite", srtpOffer(40010, "sendrecv", "1 F8_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz")},
		{"key with an MKI", srtpOffer(40010, "sendrecv", "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4")},
		{"DTLS profile", []byte(strings.Replace(string(srtpOffer(40010, "sendrecv", "x")), "RTP/SAVP", "UDP/TLS/RTP/SAVPF", 1))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := newTestInstance(t, "srtp-refuse")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ua, err := sipgo.NewUA(sipgo.WithUserAgentHostname("127.0.0.1"))
			if err != nil {
				t.Fatalf("new UA: %v", err)
			}
			t.Cleanup(func() { ua.Close() })
			client, err := sipgo.NewClient(ua, sipgo.WithClientHostname("127.0.0.1"))
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			dua := sipgo.DialogUA{
				Client:     client,
				ContactHDR: sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: "caller", Host: "127.0.0.1", Port: 5060}},
			}
			recipient := sip.Uri{Scheme: "sip", User: "500", Host: "127.0.0.1", Port: inst.sipPort}
			dialog, err := dua.Invite(ctx, recipient, tt.offer, sip.NewHeader("Content-Type", "application/sdp"))
			if err != nil {
				t.Fatalf("INVITE: %v", err)
			}
			err = dialog.WaitAnswer(ctx, sipgo.AnswerOptions{})
			var dialogErr *sipgo.ErrDialogResponse
			if !errors.As(err, &dialogErr) || dialogErr.Res.StatusCode != sip.StatusNotAcceptableHere {
				t.Fatalf("offer was not refused with 488: %v", err)
			}

			resp := httpGet(t, inst.baseURL()+"/v1/legs")
			var legs []legView
			decodeJSON(t, resp, &legs)
			if len(legs) != 0 {
				t.Errorf("a refused offer left %d leg(s) behind", len(legs))
			}
		})
	}
}

// answerWithSDP replies 200 OK to an INVITE with the given SDP.
func (c *rawSIPClient) answerWithSDP(t *testing.T, e inviteEvent, sdp []byte) {
	t.Helper()
	res := sip.NewResponseFromRequest(e.req, sip.StatusOK, "OK", sdp)
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Scheme: "sip", Host: c.host, Port: c.port}})
	if err := e.tx.Respond(res); err != nil {
		t.Fatalf("respond 200: %v", err)
	}
	close(e.done)
}

func createLegTo(t *testing.T, inst *testInstance, ua *rawSIPClient, extra map[string]interface{}) legView {
	t.Helper()
	body := map[string]interface{}{
		"type":   "sip",
		"uri":    ua.contactURI("peer"),
		"codecs": []string{"PCMU"},
	}
	for k, v := range extra {
		body[k] = v
	}
	resp := httpPost(t, inst.baseURL()+"/v1/legs", body)
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create leg: status %d: %s", resp.StatusCode, b)
	}
	var lv legView
	decodeJSON(t, resp, &lv)
	return lv
}

func expectDisconnectReason(t *testing.T, inst *testInstance, legID, want string) {
	t.Helper()
	e := inst.collector.waitForMatch(t, events.LegDisconnected, forLeg(legID), 5*time.Second)
	if got := e.Data.(*events.LegDisconnectedData).CDR.Reason; got != want {
		t.Errorf("disconnect reason = %q, want %q", got, want)
	}
}

// TestSRTP_OutboundOffer checks what the engine offers and how it treats each
// kind of answer when the leg was created with srtp required.
func TestSRTP_OutboundOffer(t *testing.T) {
	const peerKey = "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"

	t.Run("offer and SRTP answer", func(t *testing.T) {
		inst := newTestInstance(t, "srtp-out")
		ua := newRawSIPClient(t, "srtp-peer")
		wire := newSRTPWire(t)
		lv := createLegTo(t, inst, ua, map[string]interface{}{"srtp": "required"})

		e := ua.waitInvite(t, 5*time.Second)
		offer := e.req.Body()
		if !strings.Contains(string(offer), " RTP/SAVP 0 101\r\n") {
			t.Fatalf("offer is not on RTP/SAVP:\n%s", offer)
		}
		lines := sdpAttr(t, offer, "crypto")
		if len(lines) != 1 || !strings.HasPrefix(lines[0], "1 AES_CM_128_HMAC_SHA1_80 inline:") {
			t.Fatalf("offer crypto lines = %q, want one AES_CM_128_HMAC_SHA1_80 line", lines)
		}
		parsed, err := sipmod.ParseSDP(offer)
		if err != nil {
			t.Fatalf("parse offer: %v", err)
		}

		ua.answerWithSDP(t, e, srtpOffer(wire.port(), "sendrecv", peerKey))
		waitForLegState(t, inst.baseURL(), lv.ID, "connected", 5*time.Second)
		assertLegSRTP(t, inst, lv.ID, true)

		wire.keys(peerKey, lines[0], parsed.RemotePort)
		pkt, size := wire.expectSRTP("after answer")
		if len(pkt.Payload) != 160 || size != 12+160+10 {
			t.Errorf("engine packet: %d payload bytes, %d on the wire, want 160 and 182", len(pkt.Payload), size)
		}
		tap := &countingTap{}
		sl := sipLegOf(t, inst, lv.ID)
		sl.SetInTap(tap)
		defer sl.ClearInTap()
		wire.send(25)
		if !waitNonSilence(t, tap, 3*time.Second) {
			t.Fatalf("engine decoded no audio from the peer's SRTP (non-zero bytes=%d)", tap.count())
		}
		hangup(t, inst, lv.ID)
	})

	t.Run("plain answer ends the call", func(t *testing.T) {
		inst := newTestInstance(t, "srtp-out-plain")
		ua := newRawSIPClient(t, "plain-peer")
		lv := createLegTo(t, inst, ua, map[string]interface{}{"srtp": "required"})

		e := ua.waitInvite(t, 5*time.Second)
		ua.answerWithSDP(t, e, srtpOffer(40020, "sendrecv"))
		expectDisconnectReason(t, inst, lv.ID, "not_acceptable")
		select {
		case <-ua.byes:
		case <-time.After(3 * time.Second):
			t.Error("no BYE followed the plain answer")
		}
		if inst.collector.hasEvent(events.LegConnected, forLeg(lv.ID)) {
			t.Error("leg reported connected on a plain answer to an SRTP offer")
		}
	})

	t.Run("488 is not retried as plain RTP", func(t *testing.T) {
		inst := newTestInstance(t, "srtp-out-488")
		ua := newRawSIPClient(t, "refusing-peer")
		lv := createLegTo(t, inst, ua, map[string]interface{}{"srtp": "required"})

		e := ua.waitInvite(t, 5*time.Second)
		res := sip.NewResponseFromRequest(e.req, sip.StatusNotAcceptableHere, "Not Acceptable Here", nil)
		if err := e.tx.Respond(res); err != nil {
			t.Fatalf("respond 488: %v", err)
		}
		close(e.done)
		expectDisconnectReason(t, inst, lv.ID, "not_acceptable")
		select {
		case <-ua.invites:
			t.Fatal("a second INVITE followed the 488: the leg fell back")
		case <-time.After(700 * time.Millisecond):
		}
	})

	t.Run("default offer is plain", func(t *testing.T) {
		inst := newTestInstance(t, "srtp-out-default")
		ua := newRawSIPClient(t, "default-peer")
		lv := createLegTo(t, inst, ua, nil)

		e := ua.waitInvite(t, 5*time.Second)
		offer := string(e.req.Body())
		if !strings.Contains(offer, " RTP/AVP 0 101\r\n") || strings.Contains(offer, "a=crypto") {
			t.Fatalf("default offer is not plain RTP:\n%s", offer)
		}
		ua.answerWithSDP(t, e, srtpOffer(40022, "sendrecv"))
		waitForLegState(t, inst.baseURL(), lv.ID, "connected", 5*time.Second)
		assertLegSRTP(t, inst, lv.ID, false)
		hangup(t, inst, lv.ID)
	})
}

// TestSRTP_ForkedInvite checks every branch of a forked INVITE carries the
// same SRTP offer and the winner's answer is keyed.
func TestSRTP_ForkedInvite(t *testing.T) {
	inst := newTestInstance(t, "srtp-fork")
	cli1 := newRawSIPClient(t, "alice-ua-1")
	cli2 := newRawSIPClient(t, "alice-ua-2")
	cli1.sendRegister(t, inst.sipPort, "alice", cli1.contactURI("alice"), 600)
	cli2.sendRegister(t, inst.sipPort, "alice", cli2.contactURI("alice"), 600)

	resp := httpPost(t, inst.baseURL()+"/v1/legs", map[string]interface{}{
		"type":   "sip",
		"to":     "sip:alice@vb.test",
		"from":   "support",
		"codecs": []string{"PCMU"},
		"srtp":   "required",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create leg: %d", resp.StatusCode)
	}
	var lv legView
	decodeJSON(t, resp, &lv)

	e1 := cli1.waitInvite(t, 5*time.Second)
	e2 := cli2.waitInvite(t, 5*time.Second)
	c1, c2 := sdpAttr(t, e1.req.Body(), "crypto"), sdpAttr(t, e2.req.Body(), "crypto")
	if len(c1) != 1 || len(c2) != 1 || c1[0] != c2[0] {
		t.Fatalf("branches offer different keys: %q and %q", c1, c2)
	}

	wire := newSRTPWire(t)
	const peerKey = "1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR"
	cli2.answerWithSDP(t, e2, srtpOffer(wire.port(), "sendrecv", peerKey))
	waitForLegState(t, inst.baseURL(), lv.ID, "connected", 5*time.Second)
	assertLegSRTP(t, inst, lv.ID, true)

	offer, err := sipmod.ParseSDP(e2.req.Body())
	if err != nil {
		t.Fatalf("parse offer: %v", err)
	}
	wire.keys(peerKey, c2[0], offer.RemotePort)
	wire.expectSRTP("forked call")
	hangup(t, inst, lv.ID)
}

// TestSRTP_CreateLegValidation checks the srtp field is validated up front.
func TestSRTP_CreateLegValidation(t *testing.T) {
	inst := newTestInstance(t, "srtp-validate")
	for name, body := range map[string]map[string]interface{}{
		"unknown value":     {"type": "sip", "uri": "sip:x@127.0.0.1:1", "srtp": "optional"},
		"no off value":      {"type": "sip", "uri": "sip:x@127.0.0.1:1", "srtp": "off"},
		"combined with rtt": {"type": "sip", "uri": "sip:x@127.0.0.1:1", "srtp": "required", "rtt": true},
	} {
		resp := httpPost(t, inst.baseURL()+"/v1/legs", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, resp.StatusCode)
		}
	}
}
