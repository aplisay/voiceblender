package leg

import (
	"strconv"
	"strings"
	"testing"

	sipmod "github.com/VoiceBlender/voiceblender/internal/sip"
)

const (
	srtpTestKeyA = "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
	srtpTestKeyB = "PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR"
)

// srtpSDP is a one-section offer or answer. An empty key gives plain RTP/AVP.
func srtpSDP(port int, direction, key string) string {
	lines := []string{
		"v=0",
		"o=- 1 1 IN IP4 192.0.2.9",
		"s=-",
		"c=IN IP4 192.0.2.9",
		"t=0 0",
	}
	if key == "" {
		lines = append(lines, "m=audio "+strconv.Itoa(port)+" RTP/AVP 0 101")
	} else {
		lines = append(lines,
			"m=audio "+strconv.Itoa(port)+" RTP/SAVP 0 101",
			"a=crypto:5 AES_CM_128_HMAC_SHA1_32 inline:"+key,
		)
	}
	lines = append(lines,
		"a=rtpmap:0 PCMU/8000",
		"a=rtpmap:101 telephone-event/8000",
		"a="+direction,
		"",
	)
	return strings.Join(lines, "\r\n")
}

// cryptoLine returns the a=crypto value of an SDP body, or "".
func cryptoLine(body []byte) string {
	for _, line := range strings.Split(string(body), "\r\n") {
		if v, ok := strings.CutPrefix(line, "a=crypto:"); ok {
			return v
		}
	}
	return ""
}

// newSecureLeg answers an RTP/SAVP offer and returns the leg with the a=crypto
// value its answer carried.
func newSecureLeg(t *testing.T) (*SIPLeg, string) {
	t.Helper()
	l := newAnswerLeg(t, srtpSDP(40000, sipmod.DirSendRecv, srtpTestKeyA))
	answer, err := l.negotiateInboundAnswer(0)
	if err != nil {
		t.Fatalf("negotiateInboundAnswer: %v", err)
	}
	crypto := cryptoLine(answer)
	if crypto == "" {
		t.Fatalf("answer to an RTP/SAVP offer carries no crypto line:\n%s", answer)
	}
	return l, crypto
}

func TestNegotiateInboundAnswer_SRTP(t *testing.T) {
	l := newAnswerLeg(t, srtpSDP(40000, sipmod.DirSendRecv, srtpTestKeyA))
	answer, err := l.negotiateInboundAnswer(0)
	if err != nil {
		t.Fatalf("negotiateInboundAnswer: %v", err)
	}
	got := string(answer)
	if !strings.Contains(got, " RTP/SAVP 0 101\r\n") {
		t.Errorf("answer is not on RTP/SAVP:\n%s", got)
	}
	crypto, err := sipmod.ParseCrypto(cryptoLine(answer))
	if err != nil {
		t.Fatalf("answer crypto line: %v\n%s", err, got)
	}
	if crypto.Tag != 5 || crypto.Suite != sipmod.SRTPSuiteAES128SHA1_32 {
		t.Errorf("answer crypto = tag %d %s, want the offered tag 5 and suite", crypto.Tag, crypto.Suite)
	}
	if strings.Contains(got, srtpTestKeyA) {
		t.Error("answer repeats the offerer's key")
	}
	if !l.srtpActive() {
		t.Error("leg does not report SRTP after answering an RTP/SAVP offer")
	}
}

func TestNegotiateInboundAnswer_PlainOfferStaysPlain(t *testing.T) {
	l := newAnswerLeg(t, srtpSDP(40000, sipmod.DirSendRecv, ""))
	answer, err := l.negotiateInboundAnswer(0)
	if err != nil {
		t.Fatalf("negotiateInboundAnswer: %v", err)
	}
	if got := string(answer); !strings.Contains(got, " RTP/AVP 0 101\r\n") || strings.Contains(got, "a=crypto") {
		t.Errorf("plain offer was not answered as plain RTP:\n%s", got)
	}
	if l.srtpActive() {
		t.Error("leg reports SRTP after a plain offer")
	}
}

func TestNegotiateInboundAnswer_UnusableSRTPFails(t *testing.T) {
	offer := strings.Replace(srtpSDP(40000, sipmod.DirSendRecv, srtpTestKeyA),
		"AES_CM_128_HMAC_SHA1_32", "F8_128_HMAC_SHA1_80", 1)
	l := newAnswerLeg(t, offer)
	if _, err := l.negotiateInboundAnswer(0); err == nil {
		t.Error("an offer with no supported crypto suite was answered")
	}
}

// A re-offer with the same key, as a hold or a session refresh sends, must be
// answered with our same key: a new one would reset the peer's context.
func TestApplyRemoteOffer_SRTPKeepsKey(t *testing.T) {
	l, crypto := newSecureLeg(t)

	for _, direction := range []string{sipmod.DirSendOnly, sipmod.DirSendRecv} {
		answer, got := l.ApplyRemoteOffer([]byte(srtpSDP(40000, direction, srtpTestKeyA)))
		if got != direction {
			t.Errorf("direction = %q, want %q", got, direction)
		}
		if !strings.Contains(string(answer), " RTP/SAVP 0 101\r\n") {
			t.Errorf("%s re-offer answered off RTP/SAVP:\n%s", direction, answer)
		}
		if after := cryptoLine(answer); after != crypto {
			t.Errorf("%s re-offer changed our key:\n was %s\n now %s", direction, crypto, after)
		}
	}
}

func TestApplyRemoteOffer_SRTPRekey(t *testing.T) {
	l, crypto := newSecureLeg(t)
	answer, _ := l.ApplyRemoteOffer([]byte(srtpSDP(40000, sipmod.DirSendRecv, srtpTestKeyB)))
	if after := cryptoLine(answer); after != crypto {
		t.Errorf("a new remote key changed our own:\n was %s\n now %s", crypto, after)
	}
}

func TestApplyRemoteOffer_PlainLegUpgradesToSRTP(t *testing.T) {
	l := newReofferLeg(t)
	answer, _ := l.ApplyRemoteOffer([]byte(srtpSDP(41000, sipmod.DirSendRecv, srtpTestKeyA)))
	if cryptoLine(answer) == "" || !l.srtpActive() {
		t.Errorf("an RTP/SAVP re-offer on a plain leg was not taken up:\n%s", answer)
	}
}

func TestRefusesOffer(t *testing.T) {
	secure, _ := newSecureLeg(t)
	plain := newReofferLeg(t)
	unusable := strings.Replace(srtpSDP(40000, sipmod.DirSendRecv, srtpTestKeyA),
		"AES_CM_128_HMAC_SHA1_32", "F8_128_HMAC_SHA1_80", 1)

	cases := []struct {
		name  string
		leg   *SIPLeg
		offer string
		want  bool
	}{
		{"SRTP leg, plain re-offer", secure, srtpSDP(40000, sipmod.DirSendRecv, ""), true},
		{"SRTP leg, plain hold", secure, srtpSDP(40000, sipmod.DirSendOnly, ""), true},
		{"SRTP leg, no usable suite", secure, unusable, true},
		{"SRTP leg, SRTP re-offer", secure, srtpSDP(40000, sipmod.DirSendRecv, srtpTestKeyA), false},
		{"SRTP leg, new key", secure, srtpSDP(40000, sipmod.DirSendRecv, srtpTestKeyB), false},
		{"SRTP leg, unreadable body", secure, "not sdp", false},
		{"plain leg, plain re-offer", plain, srtpSDP(40000, sipmod.DirSendRecv, ""), false},
		{"plain leg, SRTP re-offer", plain, srtpSDP(40000, sipmod.DirSendRecv, srtpTestKeyA), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.leg.RefusesOffer([]byte(tc.offer)); got != tc.want {
				t.Errorf("RefusesOffer = %v, want %v", got, tc.want)
			}
		})
	}
}

// Every offer the leg builds itself (hold, resume, session refresh, the
// fallback bodies) must stay on RTP/SAVP with the key already in use.
func TestOwnOffers_SRTPLegKeepsCrypto(t *testing.T) {
	l, crypto := newSecureLeg(t)
	bodies := map[string][]byte{
		"hold":            l.reInviteSDP(sipmod.DirSendOnly),
		"resume":          l.reInviteSDP(sipmod.DirSendRecv),
		"session refresh": l.ReInviteAnswerSDP(sipmod.DirSendRecv),
		"table offer":     l.offerFromTable(),
	}
	for name, body := range bodies {
		if !strings.Contains(string(body), " RTP/SAVP ") {
			t.Errorf("%s offer is not on RTP/SAVP:\n%s", name, body)
		}
		if got := cryptoLine(body); got != crypto {
			t.Errorf("%s offer crypto = %q, want %q", name, got, crypto)
		}
	}

	plain := newReofferLeg(t)
	if body := plain.reInviteSDP(sipmod.DirSendOnly); strings.Contains(string(body), "SAVP") || cryptoLine(body) != "" {
		t.Errorf("a plain leg's hold offer mentions SRTP:\n%s", body)
	}
}

// An answer to our own offer that drops SRTP must change nothing: not the keys
// and not the address media is sent to.
func TestApplyAnswer_PlainAnswerOnSRTPLegIsIgnored(t *testing.T) {
	l, crypto := newSecureLeg(t)
	before := l.prim.rtpSess.RemoteAddr().String()

	l.applyAnswer([]byte(srtpSDP(45000, sipmod.DirSendRecv, "")))

	if got := l.prim.rtpSess.RemoteAddr().String(); got != before {
		t.Errorf("remote address moved to %s on a plain answer", got)
	}
	if got := l.prim.rtpSess.LocalCrypto(); got != crypto || !l.srtpActive() {
		t.Errorf("plain answer changed the SRTP state: crypto %q", got)
	}

	l.applyAnswer([]byte(srtpSDP(45000, sipmod.DirSendRecv, srtpTestKeyB)))
	if got := l.prim.rtpSess.RemoteAddr().String(); !strings.HasSuffix(got, ":45000") {
		t.Errorf("an SRTP answer did not move the remote address: %s", got)
	}
}

// With a plain primary stream the leg as a whole does not require SRTP, so the
// stream itself must refuse a re-offer that takes it back to plain RTP.
func TestApplyRemoteOffer_SecondaryStreamCannotDowngrade(t *testing.T) {
	offer := func(secondKey string) string {
		lines := []string{
			"v=0", "o=- 1 1 IN IP4 192.0.2.9", "s=-", "c=IN IP4 192.0.2.9", "t=0 0",
			"m=audio 40000 RTP/AVP 0", "a=rtpmap:0 PCMU/8000", "a=mid:a",
		}
		if secondKey == "" {
			lines = append(lines, "m=audio 40002 RTP/AVP 0")
		} else {
			lines = append(lines, "m=audio 40002 RTP/SAVP 0", "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:"+secondKey)
		}
		lines = append(lines, "a=rtpmap:0 PCMU/8000", "a=mid:b", "")
		return strings.Join(lines, "\r\n")
	}

	l := newAnswerLeg(t, offer(srtpTestKeyA))
	answer, err := l.negotiateInboundAnswer(0)
	if err != nil {
		t.Fatalf("negotiateInboundAnswer: %v", err)
	}
	if got := string(answer); strings.Count(got, " RTP/SAVP ") != 1 || strings.Count(got, " RTP/AVP ") != 1 {
		t.Fatalf("want one plain and one SRTP section:\n%s", got)
	}
	if l.srtpActive() {
		t.Fatal("a leg with a plain primary stream reports SRTP")
	}

	answer, _ = l.ApplyRemoteOffer([]byte(offer("")))
	got := string(answer)
	if strings.Contains(got, "SAVP") || !strings.Contains(got, "m=audio 0 RTP/AVP 0") {
		t.Errorf("the SRTP stream was not rejected when re-offered as plain RTP:\n%s", got)
	}
	if n := l.StreamCount(); n != 1 {
		t.Errorf("leg has %d streams after the refused downgrade, want 1", n)
	}
}
