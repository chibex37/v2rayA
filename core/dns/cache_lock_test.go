package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const lockTestGets = 6

func lockTestRecords(name string, n int) []dns.RR {
	rrs := make([]dns.RR, 0, n)
	for i := 0; i < n; i++ {
		rrs = append(rrs, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)),
		})
	}
	return rrs
}

func lockTestRawMsgResponse(n int) *DnsResponse {
	m := new(dns.Msg)
	m.SetQuestion("big.example.com.", dns.TypeA)
	m.Response = true
	m.Answer = lockTestRecords("big.example.com.", n)
	return &DnsResponse{RawMsg: m, Rcode: dns.RcodeSuccess, Answer: m.Answer, TTL: 300}
}

func lockTestPlainResponse(answer, authority, additional int) *DnsResponse {
	return &DnsResponse{
		Rcode:      dns.RcodeSuccess,
		Answer:     lockTestRecords("big.example.com.", answer),
		Authority:  lockTestRecords("big.example.com.", authority),
		Additional: lockTestRecords("big.example.com.", additional),
		TTL:        300,
	}
}

func newLockTestCache() *DnsCache {
	return NewDnsCache(&CacheConfig{Enabled: true, Size: 100, MinTTL: 60, MaxTTL: 86400,
		Prefetch: true, PrefetchThreshold: 30, NegativeCache: true})
}

func lockTestKey(name string) CacheKey {
	return CacheKey{UpstreamAddr: "8.8.8.8:53", ProxyTag: "direct", Name: name, QType: TypeA}
}

// measureCopyTime returns the fastest of three copies of resp, so the
// thresholds below are relative to the speed of the machine running the test.
func measureCopyTime(t *testing.T, resp *DnsResponse) time.Duration {
	t.Helper()
	best := time.Duration(1<<63 - 1)
	for i := 0; i < 3; i++ {
		start := time.Now()
		copyCachedResponse(resp, 0, 60)
		if d := time.Since(start); d < best {
			best = d
		}
	}
	if best < 5*time.Millisecond {
		t.Fatalf("test response is too small to measure: one copy takes only %v", best)
	}
	return best
}

// startGets runs Get on key several times in a goroutine. The returned
// channel delivers whether every Get was a hit.
func startGets(cache *DnsCache, key CacheKey) chan bool {
	done := make(chan bool)
	go func() {
		hit := true
		for i := 0; i < lockTestGets; i++ {
			if _, ok := cache.Get(key); !ok {
				hit = false
			}
		}
		done <- hit
	}()
	return done
}

// assertGetCopyOutsideLock stores resp and calls Get on it repeatedly while
// the test goroutine keeps asking for the cache lock. If Get copies the
// response while holding the lock, the lock requests wait about one copy.
func assertGetCopyOutsideLock(t *testing.T, resp *DnsResponse) {
	t.Helper()
	cache := newLockTestCache()
	key := lockTestKey("big.example.com")
	cache.Set(key, resp, 300)
	copyTime := measureCopyTime(t, resp)

	done := startGets(cache, key)
	var maxWait time.Duration
	var hit bool
	for waiting := true; waiting; {
		select {
		case hit = <-done:
			waiting = false
		default:
			t0 := time.Now()
			cache.mu.Lock()
			_ = cache.lruList.Len()
			cache.mu.Unlock()
			if w := time.Since(t0); w > maxWait {
				maxWait = w
			}
			time.Sleep(time.Millisecond)
		}
	}

	t.Logf("one copy takes %v; longest wait for the cache lock: %v", copyTime, maxWait)
	if !hit {
		t.Fatal("expected cache hit")
	}
	if maxWait > copyTime/2 {
		t.Fatalf("Get held the cache lock while copying: waited %v for the lock, one copy takes %v", maxWait, copyTime)
	}
}

func TestGetCopyOutsideLockRawMsg(t *testing.T) {
	assertGetCopyOutsideLock(t, lockTestRawMsgResponse(300000))
}

func TestGetCopyOutsideLockAnswerRecords(t *testing.T) {
	assertGetCopyOutsideLock(t, lockTestPlainResponse(300000, 0, 0))
}

func TestGetCopyOutsideLockAuthorityAndAdditional(t *testing.T) {
	assertGetCopyOutsideLock(t, lockTestPlainResponse(10, 150000, 150000))
}

// A Get on a small key must not wait for a large copy on another key.
func TestGetSmallKeyNotBlockedByLargeCopy(t *testing.T) {
	cache := newLockTestCache()
	bigKey := lockTestKey("big.example.com")
	smallKey := lockTestKey("small.example.com")
	big := lockTestRawMsgResponse(300000)
	cache.Set(bigKey, big, 300)
	cache.Set(smallKey, lockTestPlainResponse(1, 0, 0), 300)
	copyTime := measureCopyTime(t, big)

	done := startGets(cache, bigKey)
	var worst time.Duration
	var hit bool
	for waiting := true; waiting; {
		select {
		case hit = <-done:
			waiting = false
		default:
			t0 := time.Now()
			cache.Get(smallKey)
			if d := time.Since(t0); d > worst {
				worst = d
			}
			time.Sleep(time.Millisecond)
		}
	}

	t.Logf("one copy takes %v; slowest small-key Get: %v", copyTime, worst)
	if !hit {
		t.Fatal("expected cache hit")
	}
	if worst > copyTime/2 {
		t.Fatalf("small-key Get was blocked by a large copy: waited %v, one copy takes %v", worst, copyTime)
	}
}
