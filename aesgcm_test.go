package aesgcm

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type TestData struct {
	key        string // K
	plaintext  string // P
	aad        string // A
	nonce      string // IV
	ciphertext string // C + T
}

// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
var testData = []TestData{
	// Test Case 13
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"",
		"",
		"000000000000000000000000",
		"530f8afbc74536b9a963b4f1c4cb738b",
	},

	// Test Case 14
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"00000000000000000000000000000000",
		"",
		"000000000000000000000000",
		"cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
	},

	// Test Case 15
	{
		"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
		"",
		"cafebabefacedbaddecaf888",
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c",
	},

	// Test Case 16
	{
		"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"cafebabefacedbaddecaf888",
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b",
	},
}

type Aes256GcmSuite struct{}

var _ = Suite(&Aes256GcmSuite{})

func stringToHex(s string) string {
	return hex.EncodeToString([]byte(s))
}

func decodeHexString(c *C, s string) []byte {
	b, err := hex.DecodeString(s)
	c.Check(err, IsNil)
	if len(b) == 0 {
		return nil
	}
	return b
}

func (a *Aes256GcmSuite) TestNormal(c *C) {
	for _, d := range testData {
		c.Logf("%#v", d)

		key := decodeHexString(c, d.key)
		plaintext := decodeHexString(c, d.plaintext)
		nonce := decodeHexString(c, d.nonce)
		aad := decodeHexString(c, d.aad)

		g, err := NewAes256Gcm(key)
		c.Assert(err, IsNil)

		ciphertext, err := g.Seal(plaintext, aad, nonce)
		c.Assert(err, IsNil)
		c.Assert(ciphertext, DeepEquals, decodeHexString(c, d.ciphertext))

		plaintext2, err := g.Open(ciphertext, aad, nonce)
		c.Assert(err, IsNil)
		c.Assert(plaintext2, DeepEquals, plaintext)
	}
}

// Same as TestNormal, but with Not at right place
func (a *Aes256GcmSuite) testTamper(c *C, tamper func(d *TestData) bool) {
	for _, d := range testData {
		ok := tamper(&d)
		if !ok {
			continue
		}
		c.Logf("%#v", d)

		key := decodeHexString(c, d.key)
		plaintext := decodeHexString(c, d.plaintext)
		nonce := decodeHexString(c, d.nonce)
		aad := decodeHexString(c, d.aad)

		g, err := NewAes256Gcm(key)
		c.Assert(err, IsNil)

		ciphertext, err := g.Seal(plaintext, aad, nonce)
		c.Assert(err, IsNil)
		c.Assert(ciphertext, Not(DeepEquals), decodeHexString(c, d.ciphertext)) // Not here

		plaintext2, err := g.Open(ciphertext, aad, nonce)
		c.Assert(err, IsNil)
		c.Assert(plaintext2, DeepEquals, plaintext)
	}
}

// Returns "next" hex string: 019abf -> 12abc0
func tamperString(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '9':
			return 'a'
		case 'f':
			return '0'
		default:
			return r + 1
		}
	}, s)
}

func (a *Aes256GcmSuite) TestTamperKey(c *C) {
	a.testTamper(c, func(d *TestData) bool {
		d.key = tamperString(d.key)
		return true
	})
}

func (a *Aes256GcmSuite) TestTamperPlaintext(c *C) {
	a.testTamper(c, func(d *TestData) bool {
		if len(d.plaintext) == 0 {
			return false
		}
		d.plaintext = tamperString(d.plaintext)
		return true
	})
}

func (a *Aes256GcmSuite) TestTamperAad(c *C) {
	a.testTamper(c, func(d *TestData) bool {
		if len(d.aad) == 0 {
			return false
		}
		d.aad = tamperString(d.aad)
		return true
	})
}

func (a *Aes256GcmSuite) TestTamperNonce(c *C) {
	a.testTamper(c, func(d *TestData) bool {
		d.nonce = tamperString(d.nonce)
		return true
	})
}

func (a *Aes256GcmSuite) TestGenerateNonce(c *C) {
	now := uint64(time.Now().UnixNano())
	nonce1, err := GenerateNonce()
	c.Assert(err, IsNil)
	nonce2, err := GenerateNonce()
	c.Assert(err, IsNil)

	c.Assert(nonce1, HasLen, NonceSize)
	c.Assert(nonce2, HasLen, NonceSize)
	c.Assert(nonce1, Not(DeepEquals), nonce2)

	c.Assert(fmt.Sprintf("%x", nonce1), Matches, fmt.Sprintf("%x", now)[:10]+".+")
	c.Assert(fmt.Sprintf("%x", nonce2), Matches, fmt.Sprintf("%x", now)[:10]+".+")
}

func Example() {
	nonce, _ := GenerateNonce()
	key := []byte("Super Duper Secret Actually Not!") // len = KeySize
	plaintext := []byte("This will be encrypted and authenticed")
	aad := []byte("This will be authenticed only")

	g, _ := NewAes256Gcm(key)
	ciphertext, _ := g.Seal(plaintext, aad, nonce)

	plaintext2, _ := g.Open(ciphertext, aad, nonce)
	fmt.Println(reflect.DeepEqual(plaintext, plaintext2))

	// Output:
	// true
}
