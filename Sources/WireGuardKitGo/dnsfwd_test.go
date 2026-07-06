/* AVPN (Tribe, split-DNS): юнит-тесты чистой логики форвардера — суффикс-матчер, QNAME-парсер,
 * синтез/разбор IPv4/UDP с чексуммами (ядро iOS дропает пакеты с битым checksum — это ловим тут). */
package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestMatchesSuffix(t *testing.T) {
	suf := []string{"ru", "xn--p1ai", "vk.com", "yandex.net"}
	cases := []struct {
		q    string
		want bool
	}{
		{"ya.ru", true},
		{"gosuslugi.ru", true},
		{"sub.deep.gosuslugi.ru", true},
		{"ru", true},                  // сам суффикс
		{"vk.com", true},
		{"login.vk.com", true},
		{"kinopoisk.xn--p1ai", true},  // .рф punycode
		{"google.com", false},
		{"foru.com", false},           // "ru" в середине — не суффикс
		{"notvk.com", false},          // ложный суффикс без точки
		{"yandex.net.evil.com", false},
	}
	for _, c := range cases {
		if got := matchesSuffix(c.q, suf); got != c.want {
			t.Errorf("matchesSuffix(%q) = %v, want %v", c.q, got, c.want)
		}
	}
}

// buildQuery: минимальный DNS-запрос для qname
func buildQuery(qname string) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234) // id
	msg[2] = 0x01                                // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	for _, label := range splitLabels(qname) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, 0, 1, 0, 1) // root, QTYPE=A, QCLASS=IN
	return msg
}

func splitLabels(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, name[start:i])
			start = i + 1
		}
	}
	return out
}

func TestParseQName(t *testing.T) {
	q, ok := parseQName(buildQuery("Ya.RU"))
	if !ok || q != "ya.ru" {
		t.Fatalf("parseQName = %q,%v; want ya.ru,true", q, ok)
	}
	if _, ok := parseQName([]byte{1, 2, 3}); ok {
		t.Fatal("короткое сообщение должно давать false")
	}
	// QDCOUNT=0 → false
	msg := buildQuery("a.ru")
	binary.BigEndian.PutUint16(msg[4:6], 0)
	if _, ok := parseQName(msg); ok {
		t.Fatal("QDCOUNT=0 должен давать false")
	}
	// компрессия в QNAME → false (fail-open путь)
	msg2 := buildQuery("a.ru")
	msg2[12] = 0xC0
	if _, ok := parseQName(msg2); ok {
		t.Fatal("указатель-метка должна давать false")
	}
}

func TestBuildParseUDP4Roundtrip(t *testing.T) {
	src := netip.AddrFrom4([4]byte{10, 7, 0, 5})
	dst := netip.AddrFrom4([4]byte{1, 1, 1, 1})
	payload := buildQuery("example.com")
	pkt := buildUDP4(src, dst, 61001, 53, payload)

	m, ok := parseUDP4(pkt)
	if !ok {
		t.Fatal("parseUDP4 не разобрал собственный пакет")
	}
	if m.src != src || m.dst != dst || m.sport != 61001 || m.dpt != 53 {
		t.Fatalf("метаданные не совпали: %+v", m)
	}
	if string(m.payload) != string(payload) {
		t.Fatal("payload повреждён")
	}
	// чексуммы: пересчёт по собранному пакету должен сойтись с записанным
	gotIP := binary.BigEndian.Uint16(pkt[10:12])
	if want := ipChecksum(pkt[:20]); gotIP != want {
		t.Fatalf("ip checksum: got %x want %x", gotIP, want)
	}
	gotUDP := binary.BigEndian.Uint16(pkt[26:28])
	if want := udpChecksum(pkt); gotUDP != want {
		t.Fatalf("udp checksum: got %x want %x", gotUDP, want)
	}
}

func TestParseUDP4Rejects(t *testing.T) {
	src := netip.AddrFrom4([4]byte{10, 7, 0, 5})
	dst := netip.AddrFrom4([4]byte{1, 1, 1, 1})
	pkt := buildUDP4(src, dst, 1000, 53, []byte("x"))

	tcp := append([]byte{}, pkt...)
	tcp[9] = 6 // TCP
	if _, ok := parseUDP4(tcp); ok {
		t.Fatal("TCP не должен парситься как UDP")
	}
	frag := append([]byte{}, pkt...)
	frag[6] = 0x20 // fragment offset ≠ 0
	if _, ok := parseUDP4(frag); ok {
		t.Fatal("фрагмент должен отвергаться")
	}
	if _, ok := parseUDP4(pkt[:20]); ok {
		t.Fatal("обрезанный пакет должен отвергаться")
	}
}
