/* AVPN (Tribe, split-DNS форвардер, дизайн: tribe-front docs/amnezia-fork/SPLIT-DNS-FORWARDER-DESIGN.md)
 *
 * TUN-обёртка + мини-DNS-прокси: система получает виртуальный резолвер (100.100.100.53);
 * запросы с RU-суффиксами уходят на Яндекс НАПРЯМУЮ (NE-экстеншен исключает свой трафик из
 * туннеля), остальные — на 1.1.1.1 ЧЕРЕЗ туннель (инжект синтезированного пакета в Read-поток
 * WG-устройства). Не-DNS пакеты проходят байт-в-байт (fast-path: 3 сравнения, ноль копий сверх
 * пула пампа). Fail-open: любой сбой → запрос форвардится на 1.1.1.1 в туннель.
 *
 * amneziawg-go НЕ патчится: обёртка реализует tun.Device и вставляется в wgTurnOn между
 * платформенным TUN и device.NewDevice (см. // AVPN в api-apple.go).
 */
package main

import "C"

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// ── конфиг (ставится из Swift до wgTurnOn) ────────────────────────────────────────────────────

type splitDNSConfig struct {
	enabled   bool
	suffixes  []string   // "ru", "xn--p1ai", "vk.com" … — lowercase, без точек по краям
	directSrv netip.Addr // Яндекс 77.88.8.8 — RU-суффиксы, мимо туннеля
	tunnelSrv netip.Addr // 1.1.1.1 — остальное, через туннель
	virtIP    netip.Addr // 100.100.100.53 — виртуальный резолвер, который видит система
	clientIP  netip.Addr // адрес интерфейса клиента (src синтезированных пакетов)
	warmup    bool       // прогрев WG-рукопожатия при подъёме (иначе первый DNS ловит холодный туннель)
}

var (
	splitDNSMu  sync.Mutex
	splitDNSCfg *splitDNSConfig // nil = выключено (fast-path без обёртки)
)

//export wgSetSplitDns
func wgSetSplitDns(suffixesCsv *C.char, directServer *C.char, tunnelServer *C.char, clientIp *C.char, enabled int32, warmup int32) int32 {
	splitDNSMu.Lock()
	defer splitDNSMu.Unlock()
	if enabled == 0 {
		splitDNSCfg = nil
		return 0
	}
	direct, err1 := netip.ParseAddr(C.GoString(directServer))
	tunnelS, err2 := netip.ParseAddr(C.GoString(tunnelServer))
	client, err3 := netip.ParseAddr(strings.Split(C.GoString(clientIp), "/")[0])
	virt := netip.AddrFrom4([4]byte{100, 100, 100, 53})
	if err1 != nil || err2 != nil || err3 != nil {
		splitDNSCfg = nil
		return -1
	}
	var suf []string
	for _, s := range strings.Split(C.GoString(suffixesCsv), ",") {
		s = strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".")
		if s != "" {
			suf = append(suf, s)
		}
	}
	if len(suf) == 0 {
		splitDNSCfg = nil
		return -1
	}
	splitDNSCfg = &splitDNSConfig{
		enabled: true, suffixes: suf,
		directSrv: direct, tunnelSrv: tunnelS, virtIP: virt, clientIP: client,
		warmup: warmup != 0,
	}
	return 0
}

func currentSplitDNS() *splitDNSConfig {
	splitDNSMu.Lock()
	defer splitDNSMu.Unlock()
	return splitDNSCfg
}

// ── чистая логика (юнит-тесты dnsfwd_test.go) ─────────────────────────────────────────────────

// matchesSuffix: qname принадлежит суффиксу (равен ему или заканчивается на ".суффикс").
// qname уже lowercase без хвостовой точки.
func matchesSuffix(qname string, suffixes []string) bool {
	for _, s := range suffixes {
		if qname == s || strings.HasSuffix(qname, "."+s) {
			return true
		}
	}
	return false
}

// parseQName: первый QNAME из DNS-запроса (payload = DNS-сообщение без IP/UDP). Компрессии в
// Question-секции запросов не бывает (указатели → false, fail-open). Возвращает lowercase.
func parseQName(msg []byte) (string, bool) {
	if len(msg) < 12 {
		return "", false
	}
	if qd := binary.BigEndian.Uint16(msg[4:6]); qd == 0 {
		return "", false
	}
	var b strings.Builder
	i := 12
	for {
		if i >= len(msg) {
			return "", false
		}
		l := int(msg[i])
		if l == 0 {
			break
		}
		if l&0xC0 != 0 { // компрессия/расширенные метки в запросе — не наш случай
			return "", false
		}
		i++
		if i+l > len(msg) || b.Len() > 253 {
			return "", false
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(msg[i : i+l])
		i += l
	}
	return strings.ToLower(b.String()), true
}

// ── IPv4/UDP пакеты (синтез и разбор; только v4 — v6-DNS система при v4-резолвере не шлёт) ────

type udpMeta struct {
	src, dst   netip.Addr
	sport, dpt uint16
	payload    []byte // ссылка внутрь исходного пакета
}

// parseUDP4: разбор пакета из TUN. ok=false для любого не-IPv4/UDP/фрагмента.
func parseUDP4(pkt []byte) (udpMeta, bool) {
	var m udpMeta
	if len(pkt) < 28 || pkt[0]>>4 != 4 {
		return m, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+8 || pkt[9] != 17 { // 17 = UDP
		return m, false
	}
	if binary.BigEndian.Uint16(pkt[6:8])&0x3FFF != 0 { // фрагмент — не трогаем
		return m, false
	}
	m.src = netip.AddrFrom4([4]byte(pkt[12:16]))
	m.dst = netip.AddrFrom4([4]byte(pkt[16:20]))
	m.sport = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	m.dpt = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	ulen := int(binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6]))
	if ulen < 8 || ihl+ulen > len(pkt) {
		return m, false
	}
	m.payload = pkt[ihl+8 : ihl+ulen]
	return m, true
}

// buildUDP4: собрать IPv4/UDP пакет (полные чексуммы — ядро iOS их проверяет).
func buildUDP4(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	total := 28 + len(payload)
	p := make([]byte, total)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	p[6] = 0x40 // DF
	p[8] = 64   // TTL
	p[9] = 17   // UDP
	s4, d4 := src.As4(), dst.As4()
	copy(p[12:16], s4[:])
	copy(p[16:20], d4[:])
	binary.BigEndian.PutUint16(p[10:12], ipChecksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	binary.BigEndian.PutUint16(p[26:28], udpChecksum(p))
	return p
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		if i == 10 { // поле checksum
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksum(pkt []byte) uint16 {
	ulen := len(pkt) - 20
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(pkt[12:14])) + uint32(binary.BigEndian.Uint16(pkt[14:16]))
	sum += uint32(binary.BigEndian.Uint16(pkt[16:18])) + uint32(binary.BigEndian.Uint16(pkt[18:20]))
	sum += 17 + uint32(ulen)
	for i := 20; i+1 < len(pkt); i += 2 {
		if i == 26 { // поле checksum
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	if len(pkt)%2 == 1 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	c := ^uint16(sum)
	if c == 0 {
		c = 0xFFFF
	}
	return c
}

// ── mux ожидающих запросов ────────────────────────────────────────────────────────────────────

type pendingQuery struct {
	origSrc   netip.Addr // кто спрашивал (обычно clientIP)
	origSport uint16
	deadline  time.Time
}

// ── TUN-обёртка ───────────────────────────────────────────────────────────────────────────────

// fwdTun реализует tun.Device. Собственный памп читает real, маршрутизирует DNS и складывает
// остальное в out; Read устройства WG берёт из out (данные ОС + инжекты in-tunnel запросов).
// Write перехватывает ответы 1.1.1.1 на порты mux (эфемерные 61000+), остальное — в real.
type fwdTun struct {
	real tun.Device
	cfg  *splitDNSConfig

	out     chan []byte // к WG-устройству (пакеты ОС + инжект DNS-запросов в туннель)
	closed  chan struct{}
	wmu     sync.Mutex // сериализация real.Write (наши прямые ответы ОС конкурируют с WG)
	pending sync.Map   // ключ uint16 (эфемерный порт mux) → *pendingQuery
	nextEph uint32     // счётчик эфемерных портов 61000..64999
	offset  int        // offset, который использует device (запоминаем из Read)
}

const (
	fwdEphBase  = 61000
	fwdEphSpan  = 4000
	fwdOutDepth = 512
	fwdTimeout  = 3 * time.Second
	// Прогрев: sport ВНЕ mux-диапазона [fwdEphBase, fwdEphBase+fwdEphSpan) → ответ (если придёт)
	// не матчится в Write и уходит в real; ОС его отбросит (нет ожидающего сокета). Пауза даёт
	// device.Up() поднять RoutineReadFromTUN до инжекта (канал буферизован — потери нет, но чище).
	warmupSport = 50000
	warmupDelay = 150 * time.Millisecond
)

// wrapTunIfEnabled: точка входа из wgTurnOn (// AVPN в api-apple.go).
func wrapTunIfEnabled(real tun.Device, logf func(format string, args ...interface{})) tun.Device {
	cfg := currentSplitDNS()
	if cfg == nil {
		return real
	}
	f := &fwdTun{
		real:   real,
		cfg:    cfg,
		out:    make(chan []byte, fwdOutDepth),
		closed: make(chan struct{}),
		offset: -1,
	}
	go f.gcLoop()
	if cfg.warmup {
		go f.warmupHandshake()
	}
	if logf != nil {
		logf("AVPN dnsfwd: split-DNS forwarder enabled (%d suffixes, warmup=%v)", len(cfg.suffixes), cfg.warmup)
	}
	return f
}

// warmupHandshake: инжектит один прогревочный UDP-пакет в туннель сразу после подъёма, чтобы
// WG-рукопожатие состоялось ДО первого пользовательского DNS. Иначе первый резолв не-RU домена
// (resolveViaTunnel) — сам первый исходящий пакет — ждёт handshake round-trip и таймаутит на
// системном резолвере: «первый запрос мимо, второй ок» (ванильная Amnezia форвардера не имеет,
// её DNS идёт напрямую и системный резолвер сам переспрашивает). Один пакет = один
// SendHandshakeInitiation; ответ (если 1.1.1.1 ответит) уйдёт в real и ОС его отбросит.
func (f *fwdTun) warmupHandshake() {
	select {
	case <-time.After(warmupDelay):
	case <-f.closed:
		return
	}
	pkt := buildUDP4(f.cfg.clientIP, f.cfg.tunnelSrv, warmupSport, 53, warmupDNSQuery())
	select {
	case f.out <- pkt:
	case <-f.closed:
	}
}

// warmupDNSQuery: минимальный валидный DNS-запрос (root «.», A/IN) — payload прогревочного пакета.
// Содержимое неважно (цель — исходящий пакет, триггерящий рукопожатие); валидный DNS на случай,
// если 1.1.1.1 всё же ответит (ответ безвреден — уйдёт в real на неслушаемый порт).
func warmupDNSQuery() []byte {
	return []byte{
		0x77, 0x77, // id
		0x01, 0x00, // flags: RD
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // root name «.»
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
}

// pump: единственный читатель real. Стартует лениво из первого Read (когда известен offset).
func (f *fwdTun) pump(offset int) {
	batch := f.real.BatchSize()
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	for {
		n, err := f.real.Read(bufs, sizes, offset)
		if err != nil {
			select {
			case <-f.closed:
			default:
				close(f.closed)
			}
			return
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][offset : offset+sizes[i]]
			if f.tryHandleDNS(pkt) {
				continue // забрали себе — ОС ответит наш прокси
			}
			cp := make([]byte, sizes[i])
			copy(cp, pkt)
			select {
			case f.out <- cp:
			case <-f.closed:
				return
			}
		}
	}
}

// tryHandleDNS: UDP:53 к виртуальному резолверу → маршрутизация; true = пакет поглощён.
func (f *fwdTun) tryHandleDNS(pkt []byte) bool {
	m, ok := parseUDP4(pkt)
	if !ok || m.dpt != 53 || m.dst != f.cfg.virtIP {
		return false
	}
	qname, ok := parseQName(m.payload)
	query := make([]byte, len(m.payload))
	copy(query, m.payload)
	if ok && matchesSuffix(qname, f.cfg.suffixes) {
		go f.resolveDirect(m.src, m.sport, query)
	} else {
		f.resolveViaTunnel(m.src, m.sport, query) // fail-open: не распарсили — тоже в туннель
	}
	return true
}

// resolveDirect: RU-суффикс → Яндекс мимо туннеля (сокет NE-экстеншена не заворачивается в туннель).
func (f *fwdTun) resolveDirect(origSrc netip.Addr, origSport uint16, query []byte) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(f.cfg.directSrv.String(), "53"), fwdTimeout)
	if err != nil {
		f.resolveViaTunnel(origSrc, origSport, query) // fail-open
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(fwdTimeout))
	if _, err = conn.Write(query); err != nil {
		f.resolveViaTunnel(origSrc, origSport, query)
		return
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		f.resolveViaTunnel(origSrc, origSport, query)
		return
	}
	f.replyToOS(origSrc, origSport, resp[:n])
}

// resolveViaTunnel: синтезированный запрос к 1.1.1.1 инжектится в Read-поток WG (уйдёт в туннель);
// ответ перехватит Write-путь по эфемерному порту.
func (f *fwdTun) resolveViaTunnel(origSrc netip.Addr, origSport uint16, query []byte) {
	eph := f.allocEph()
	f.pending.Store(eph, &pendingQuery{origSrc: origSrc, origSport: origSport,
		deadline: time.Now().Add(fwdTimeout)})
	pkt := buildUDP4(f.cfg.clientIP, f.cfg.tunnelSrv, eph, 53, query)
	select {
	case f.out <- pkt:
	case <-f.closed:
	}
}

func (f *fwdTun) allocEph() uint16 {
	f.wmu.Lock()
	f.nextEph++
	e := fwdEphBase + uint16(f.nextEph%fwdEphSpan)
	f.wmu.Unlock()
	return e
}

// replyToOS: ответ системе — пишем в real от имени виртуального резолвера.
func (f *fwdTun) replyToOS(dst netip.Addr, dport uint16, dnsResp []byte) {
	pkt := buildUDP4(f.cfg.virtIP, dst, 53, dport, dnsResp)
	off := f.offset
	if off < 0 {
		off = 4 // darwin utun: 4-байтовый префикс семейства
	}
	buf := make([]byte, off+len(pkt))
	if off >= 4 {
		buf[off-1] = 2 // AF_INET
	}
	copy(buf[off:], pkt)
	f.wmu.Lock()
	f.real.Write([][]byte{buf}, off)
	f.wmu.Unlock()
}

func (f *fwdTun) gcLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-f.closed:
			return
		case now := <-t.C:
			f.pending.Range(func(k, v any) bool {
				if pq, ok := v.(*pendingQuery); ok && now.After(pq.deadline) {
					f.pending.Delete(k)
				}
				return true
			})
		}
	}
}

// ── tun.Device ────────────────────────────────────────────────────────────────────────────────

func (f *fwdTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if f.offset < 0 { // первый Read: узнаём offset устройства и стартуем памп
		f.wmu.Lock()
		if f.offset < 0 {
			f.offset = offset
			go f.pump(offset)
		}
		f.wmu.Unlock()
	}
	select {
	case pkt := <-f.out:
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		count := 1
		// добираем без блокировки до размера батча
		for count < len(bufs) {
			select {
			case pkt = <-f.out:
				n = copy(bufs[count][offset:], pkt)
				sizes[count] = n
				count++
			default:
				return count, nil
			}
		}
		return count, nil
	case <-f.closed:
		return 0, os.ErrClosed // любой err завершает RoutineReadFromTUN штатно
	}
}

func (f *fwdTun) Write(bufs [][]byte, offset int) (int, error) {
	kept := bufs[:0]
	for _, b := range bufs {
		pkt := b[offset:]
		if m, ok := parseUDP4(pkt); ok && m.sport == 53 && m.src == f.cfg.tunnelSrv &&
			m.dpt >= fwdEphBase && m.dpt < fwdEphBase+fwdEphSpan {
			if v, loaded := f.pending.LoadAndDelete(m.dpt); loaded {
				pq := v.(*pendingQuery)
				resp := make([]byte, len(m.payload))
				copy(resp, m.payload)
				go f.replyToOS(pq.origSrc, pq.origSport, resp)
				continue // потреблён — ОС получит ответ от virtIP
			}
		}
		kept = append(kept, b)
	}
	if len(kept) == 0 {
		return len(bufs), nil
	}
	f.wmu.Lock()
	n, err := f.real.Write(kept, offset)
	f.wmu.Unlock()
	if n == len(kept) {
		n = len(bufs)
	}
	return n, err
}

func (f *fwdTun) MTU() (int, error)        { return f.real.MTU() }
func (f *fwdTun) Name() (string, error)    { return f.real.Name() }
func (f *fwdTun) File() *os.File           { return f.real.File() }
func (f *fwdTun) Events() <-chan tun.Event { return f.real.Events() }
func (f *fwdTun) BatchSize() int           { return f.real.BatchSize() }
func (f *fwdTun) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return f.real.Close()
}
