package sip

import (
	"strings"
	"testing"

	"github.com/VoiceBlender/voiceblender/internal/codec"
)

const (
	testCrypto80 = "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
	testCrypto32 = "2 AES_CM_128_HMAC_SHA1_32 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR"
)

func sdpWith(media ...string) []byte {
	lines := append([]string{
		"v=0",
		"o=- 1 1 IN IP4 192.0.2.9",
		"s=-",
		"c=IN IP4 192.0.2.9",
		"t=0 0",
	}, media...)
	return []byte(strings.Join(append(lines, ""), "\r\n"))
}

func TestParseSDP_Crypto(t *testing.T) {
	m, err := ParseSDP(sdpWith(
		"m=audio 40000 RTP/SAVP 0 101",
		"a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVzWVNfX19zZW1jdGwgKCkgew==",
		"a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20",
		"a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4",
		"a=crypto:4 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
		"a=rtpmap:101 telephone-event/8000",
	))
	if err != nil {
		t.Fatalf("ParseSDP: %v", err)
	}
	a := m.PrimaryStream()
	if !a.SRTP {
		t.Error("RTP/SAVP section not marked SRTP")
	}
	// The unknown suite and the line with an MKI are dropped; order is kept.
	if len(a.Crypto) != 2 || a.Crypto[0].Tag != 2 || a.Crypto[1].Tag != 4 {
		t.Fatalf("usable crypto lines = %+v, want tags 2 and 4", a.Crypto)
	}
	if a.Crypto[0].Suite != SRTPSuiteAES128SHA1_32 || a.Crypto[1].Suite != SRTPSuiteAES128SHA1_80 {
		t.Errorf("suites = %s, %s", a.Crypto[0].Suite, a.Crypto[1].Suite)
	}
}

func TestParseSDP_CryptoOnlyCountsOnSAVP(t *testing.T) {
	cases := []struct {
		name, mline string
		wantSRTP    bool
	}{
		{"plain profile carrying a crypto line", "m=audio 40000 RTP/AVP 0", false},
		{"DTLS profile carrying a crypto line", "m=audio 40000 UDP/TLS/RTP/SAVPF 0", true},
		{"feedback profile carrying a crypto line", "m=audio 40000 RTP/SAVPF 0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseSDP(sdpWith(tc.mline, "a=crypto:"+testCrypto80))
			if err != nil {
				t.Fatalf("ParseSDP: %v", err)
			}
			a := m.PrimaryStream()
			if a.SRTP != tc.wantSRTP || len(a.Crypto) != 0 {
				t.Errorf("SRTP = %v with %d usable crypto lines, want %v with none", a.SRTP, len(a.Crypto), tc.wantSRTP)
			}
		})
	}
}

func TestParseSDP_PlainOfferHasNoSRTP(t *testing.T) {
	m, err := ParseSDP(sdpWith("m=audio 40000 RTP/AVP 0"))
	if err != nil {
		t.Fatalf("ParseSDP: %v", err)
	}
	if a := m.PrimaryStream(); a.SRTP || a.Crypto != nil {
		t.Errorf("plain section parsed as SRTP = %v, crypto %v", a.SRTP, a.Crypto)
	}
}

// RTT is not carried over SRTP, so a secure text section must not be taken for
// one the plain text path can answer.
func TestParseSDP_SecureTextSectionIsNotUsable(t *testing.T) {
	m, err := ParseSDP(sdpWith(
		"m=audio 40000 RTP/SAVP 0",
		"a=crypto:"+testCrypto80,
		"m=text 40002 RTP/SAVP 98",
		"a=rtpmap:98 t140/1000",
		"a=crypto:"+testCrypto80,
	))
	if err != nil {
		t.Fatalf("ParseSDP: %v", err)
	}
	if m.Text != nil {
		t.Error("an RTP/SAVP text section was parsed as usable RTT")
	}
}

func TestGenerateOffer_GoldenSRTP(t *testing.T) {
	got := GenerateOffer(SDPConfig{
		LocalIP: "192.0.2.1",
		RTPPort: 10000,
		Codecs:  []codec.CodecType{codec.CodecPCMU, codec.CodecPCMA},
		Crypto:  testCrypto80,
	})
	assertSDP(t, got, `v=0
o=<origin>
s=-
c=IN IP4 192.0.2.1
t=0 0
m=audio 10000 RTP/SAVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=sendrecv
a=rtcp-mux
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz
`)
}

func TestGenerateAnswerAndReInvite_SRTP(t *testing.T) {
	cfg := SDPConfig{LocalIP: "192.0.2.1", RTPPort: 10000, Crypto: testCrypto32}
	for name, body := range map[string][]byte{
		"answer":    GenerateAnswer(cfg, codec.CodecPCMU, 0, false),
		"re-INVITE": GenerateReInviteSDP(cfg, codec.CodecPCMU, 0, DirSendOnly),
	} {
		got := string(body)
		if !strings.Contains(got, "m=audio 10000 RTP/SAVP 0 101\r\n") {
			t.Errorf("%s is not on RTP/SAVP:\n%s", name, got)
		}
		if !strings.Contains(got, "a=crypto:"+testCrypto32+"\r\n") {
			t.Errorf("%s lacks the crypto line:\n%s", name, got)
		}
	}
}

func TestGenerateOffer_SRTPIsPerStream(t *testing.T) {
	got := string(GenerateOffer(SDPConfig{
		LocalIP: "192.0.2.1",
		Streams: []AudioStream{
			{Port: 10000, Codecs: []codec.CodecType{codec.CodecPCMU}, MID: "0", Crypto: testCrypto80},
			{Port: 10002, Codecs: []codec.CodecType{codec.CodecPCMU}, MID: "1"},
			{Port: 0, MID: "2", Crypto: testCrypto80},
		},
	}))
	for _, want := range []string{
		"m=audio 10000 RTP/SAVP 0 101\r\n",
		"m=audio 10002 RTP/AVP 0 101\r\n",
		"m=audio 0 RTP/AVP 0\r\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("offer lacks %q:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "a=crypto:"); n != 1 {
		t.Errorf("offer carries %d crypto lines, want 1:\n%s", n, got)
	}
}

func TestGeneratedSRTPOfferParsesBack(t *testing.T) {
	m, err := ParseSDP(GenerateOffer(SDPConfig{
		LocalIP: "192.0.2.1",
		RTPPort: 10000,
		Codecs:  []codec.CodecType{codec.CodecPCMU},
		Crypto:  testCrypto80,
	}))
	if err != nil {
		t.Fatalf("ParseSDP: %v", err)
	}
	a := m.PrimaryStream()
	if !a.SRTP || len(a.Crypto) != 1 || a.Crypto[0].String() != testCrypto80 {
		t.Errorf("parsed back SRTP = %v, crypto = %v", a.SRTP, a.Crypto)
	}
}

func TestPlanAnswer_SRTP(t *testing.T) {
	supported := []codec.CodecType{codec.CodecPCMU}
	plan := func(t *testing.T, require bool, media ...string) SlotPlan {
		t.Helper()
		offer, err := ParseSDP(sdpWith(media...))
		if err != nil {
			t.Fatalf("ParseSDP: %v", err)
		}
		plans := PlanAnswer(offer, AnswerOptions{SupportedCodecs: supported, TextMLineIndex: -1, RequireSRTP: require})
		if len(plans) != 1 {
			t.Fatalf("got %d plans, want 1", len(plans))
		}
		return plans[0]
	}

	t.Run("SAVP with a usable key is accepted", func(t *testing.T) {
		p := plan(t, false, "m=audio 40000 RTP/SAVP 0", "a=crypto:"+testCrypto80)
		if p.Action != SlotAccept {
			t.Errorf("action = %v, reason %q", p.Action, p.Reason)
		}
	})
	t.Run("SAVP with no usable key is rejected", func(t *testing.T) {
		p := plan(t, false, "m=audio 40000 RTP/SAVP 0", "a=crypto:1 F8_128_HMAC_SHA1_80 inline:abcd")
		if p.Action != SlotReject || p.Reason != "unsupported_srtp" {
			t.Errorf("action = %v, reason %q", p.Action, p.Reason)
		}
	})
	t.Run("DTLS-SRTP is rejected", func(t *testing.T) {
		p := plan(t, false, "m=audio 40000 UDP/TLS/RTP/SAVPF 0")
		if p.Action != SlotReject || p.Reason != "unsupported_srtp" {
			t.Errorf("action = %v, reason %q", p.Action, p.Reason)
		}
	})
	t.Run("plain RTP is accepted on a plain leg", func(t *testing.T) {
		if p := plan(t, false, "m=audio 40000 RTP/AVP 0"); p.Action != SlotAccept {
			t.Errorf("action = %v, reason %q", p.Action, p.Reason)
		}
	})
	t.Run("plain RTP is rejected once SRTP is required", func(t *testing.T) {
		p := plan(t, true, "m=audio 40000 RTP/AVP 0")
		if p.Action != SlotReject || p.Reason != "srtp_required" {
			t.Errorf("action = %v, reason %q", p.Action, p.Reason)
		}
	})
	t.Run("SAVP is accepted when SRTP is required", func(t *testing.T) {
		p := plan(t, true, "m=audio 40000 RTP/SAVP 0", "a=crypto:"+testCrypto80)
		if p.Action != SlotAccept {
			t.Errorf("action = %v, reason %q", p.Action, p.Reason)
		}
	})
}

// A phone that offers SRTP and plain RTP as alternatives gets the first one it
// listed. The order decides, and a plain section never rides beside SRTP audio.
func TestPlanAnswer_SRTPAndPlainAlternatives(t *testing.T) {
	supported := []codec.CodecType{codec.CodecPCMU}
	secure := []string{"m=audio 40000 RTP/SAVP 0", "a=crypto:" + testCrypto80}
	plain := []string{"m=audio 40000 RTP/AVP 0"}

	plan := func(t *testing.T, media []string) []SlotPlan {
		t.Helper()
		offer, err := ParseSDP(sdpWith(media...))
		if err != nil {
			t.Fatalf("ParseSDP: %v", err)
		}
		return PlanAnswer(offer, AnswerOptions{SupportedCodecs: supported, TextMLineIndex: -1})
	}

	got := plan(t, append(append([]string{}, secure...), plain...))
	if got[0].Action != SlotAccept || got[1].Action != SlotReject || got[1].Reason != "srtp_required" {
		t.Errorf("SRTP first: actions %v, %v (%q), want accept then reject", got[0].Action, got[1].Action, got[1].Reason)
	}

	got = plan(t, append(append([]string{}, plain...), secure...))
	if got[0].Action != SlotAccept || got[1].Action != SlotAccept {
		t.Errorf("plain first: actions %v, %v, want both accepted as before", got[0].Action, got[1].Action)
	}
}

func TestAcceptSRTPAnswer_Helper(t *testing.T) {
	answer := func(media ...string) *SDPMedia {
		m, err := ParseSDP(sdpWith(media...))
		if err != nil {
			t.Fatalf("ParseSDP: %v", err)
		}
		return m
	}
	secureAnswer := answer("m=audio 40000 RTP/SAVP 0", "a=crypto:"+testCrypto80)
	plainAnswer := answer("m=audio 40000 RTP/AVP 0")

	plain := newLoopbackRTPSession(t)
	if err := acceptSRTPAnswer(plain, secureAnswer); err != nil || plain.Secure() {
		t.Errorf("a plain offer must ignore crypto in the answer: err %v, secure %v", err, plain.Secure())
	}

	sess := newLoopbackRTPSession(t)
	if _, err := sess.OfferSRTP(); err != nil {
		t.Fatalf("OfferSRTP: %v", err)
	}
	if err := acceptSRTPAnswer(sess, plainAnswer); err == nil {
		t.Error("a plain answer to an SRTP offer was accepted")
	}
	if err := acceptSRTPAnswer(sess, secureAnswer); err != nil {
		t.Errorf("an SRTP answer was refused: %v", err)
	}
}
