package prober

import (
	"context"
	"errors"
	// "net"

	"github.com/emmanuel/blackbox-exporter/internal/config"
	"github.com/emmanuel/blackbox-exporter/internal/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type icmpProbe struct {
	name   string
	module *config.Module
}

func NewICMP(name string, module *config.Module) Prober {
	return &icmpProbe{
		name:   name,
		module: module,
	}
}

func (this *icmpProbe) Probe(ctx context.Context, target string, registry *prometheus.Registry, logger *zap.Logger) error {
	m := metrics.NewICMPProbeMetrics(registry)
	log := logger.With(zap.String("module", this.name))
	m.SetPhaseDurationMetric(metrics.ProbeICMPDurationPhaseResolve, 0)

	log.Info("probing ICMP target")
	return errors.New("Not implemented")
}

// var (
// 	icmpSequence      uint16
// 	icmpSequenceMutex sync.Mutex
// )
//
// func getICMPSequence() uint16 {
// 	icmpSequenceMutex.Lock()
// 	defer icmpSequenceMutex.Unlock()
// 	icmpSequence++
// 	return icmpSequence
// }
//
// func ProbeICMP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
// 	var (
// 		socket      net.PacketConn
// 		requestType icmp.Type
// 		replyType   icmp.Type
//
// 		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
// 			Name: "probe_icmp_duration_seconds",
// 			Help: "Duration of icmp request by phase",
// 		}, []string{"phase"})
// 	)
//
// 	for _, lv := range []string{"resolve", "setup", "rtt"} {
// 		durationGaugeVec.WithLabelValues(lv)
// 	}
//
// 	registry.MustRegister(durationGaugeVec)
//
// 	timeoutDeadline, _ := ctx.Deadline()
// 	deadline := time.Now().Add(timeoutDeadline.Sub(time.Now()))
//
// 	ip, lookupTime, err := chooseProtocol(module.ICMP.PreferredIPProtocol, target, registry, logger)
// 	if err != nil {
// 		level.Warn(logger).Log("msg", "Error resolving address", "err", err)
// 		return false
// 	}
// 	durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)
//
// 	var srcIP net.IP
// 	if len(module.ICMP.SourceIPAddress) > 0 {
// 		if srcIP = net.ParseIP(module.ICMP.SourceIPAddress); srcIP == nil {
// 			level.Error(logger).Log("msg", "Error parsing source ip address", "srcIP", module.ICMP.SourceIPAddress)
// 			return false
// 		}
// 		level.Info(logger).Log("msg", "Using source address", "srcIP", srcIP)
// 	}
//
// 	setupStart := time.Now()
// 	level.Info(logger).Log("msg", "Creating socket")
// 	if ip.IP.To4() == nil {
// 		requestType = ipv6.ICMPTypeEchoRequest
// 		replyType = ipv6.ICMPTypeEchoReply
//
// 		if srcIP == nil {
// 			srcIP = net.ParseIP("::")
// 		}
// 		icmpConn, err := icmp.ListenPacket("ip6:ipv6-icmp", srcIP.String())
// 		if err != nil {
// 			level.Error(logger).Log("msg", "Error listening to socket", "err", err)
// 			return
// 		}
//
// 		socket = icmpConn
// 	} else {
// 		requestType = ipv4.ICMPTypeEcho
// 		replyType = ipv4.ICMPTypeEchoReply
//
// 		if srcIP == nil {
// 			srcIP = net.ParseIP("0.0.0.0")
// 		}
// 		icmpConn, err := net.ListenPacket("ip4:icmp", srcIP.String())
// 		if err != nil {
// 			level.Error(logger).Log("msg", "Error listening to socket", "err", err)
// 			return
// 		}
//
// 		if module.ICMP.DontFragment {
// 			rc, err := ipv4.NewRawConn(icmpConn)
// 			if err != nil {
// 				level.Error(logger).Log("msg", "Error creating raw connection", "err", err)
// 				return
// 			}
// 			socket = &v4Conn{c: rc, df: true}
// 		} else {
// 			socket = icmpConn
// 		}
// 	}
//
// 	defer socket.Close()
//
// 	var data []byte
// 	if module.ICMP.PayloadSize != 0 {
// 		data = make([]byte, module.ICMP.PayloadSize)
// 		copy(data, "Prometheus Blackbox Exporter")
// 	} else {
// 		data = []byte("Prometheus Blackbox Exporter")
// 	}
//
// 	body := &icmp.Echo{
// 		ID:   os.Getpid() & 0xffff,
// 		Seq:  int(getICMPSequence()),
// 		Data: data,
// 	}
// 	level.Info(logger).Log("msg", "Creating ICMP packet", "seq", body.Seq, "id", body.ID)
// 	wm := icmp.Message{
// 		Type: requestType,
// 		Code: 0,
// 		Body: body,
// 	}
//
// 	wb, err := wm.Marshal(nil)
// 	if err != nil {
// 		level.Error(logger).Log("msg", "Error marshalling packet", "err", err)
// 		return
// 	}
// 	durationGaugeVec.WithLabelValues("setup").Add(time.Since(setupStart).Seconds())
// 	level.Info(logger).Log("msg", "Writing out packet")
// 	rttStart := time.Now()
// 	if _, err = socket.WriteTo(wb, ip); err != nil {
// 		level.Warn(logger).Log("msg", "Error writing to socket", "err", err)
// 		return
// 	}
//
// 	// Reply should be the same except for the message type.
// 	wm.Type = replyType
// 	wb, err = wm.Marshal(nil)
// 	if err != nil {
// 		level.Error(logger).Log("msg", "Error marshalling packet", "err", err)
// 		return
// 	}
//
// 	rb := make([]byte, 65536)
// 	if err := socket.SetReadDeadline(deadline); err != nil {
// 		level.Error(logger).Log("msg", "Error setting socket deadline", "err", err)
// 		return
// 	}
// 	level.Info(logger).Log("msg", "Waiting for reply packets")
// 	for {
// 		n, peer, err := socket.ReadFrom(rb)
// 		if err != nil {
// 			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
// 				level.Warn(logger).Log("msg", "Timeout reading from socket", "err", err)
// 				return
// 			}
// 			level.Error(logger).Log("msg", "Error reading from socket", "err", err)
// 			continue
// 		}
// 		if peer.String() != ip.String() {
// 			continue
// 		}
// 		if replyType == ipv6.ICMPTypeEchoReply {
// 			// Clear checksum to make comparison succeed.
// 			rb[2] = 0
// 			rb[3] = 0
// 		}
// 		if bytes.Compare(rb[:n], wb) == 0 {
// 			durationGaugeVec.WithLabelValues("rtt").Add(time.Since(rttStart).Seconds())
// 			level.Info(logger).Log("msg", "Found matching reply packet")
// 			return true
// 		}
// 	}
// }
//
// type v4Conn struct {
// 	c *ipv4.RawConn
//
// 	df  bool
// 	src net.IP
// }
//
// func (c *v4Conn) ReadFrom(b []byte) (int, net.Addr, error) {
// 	h, p, _, err := c.c.ReadFrom(b)
// 	if err != nil {
// 		return 0, nil, err
// 	}
//
// 	copy(b, p)
// 	n := len(b)
// 	if len(p) < len(b) {
// 		n = len(p)
// 	}
// 	return n, &net.IPAddr{IP: h.Src}, nil
// }
//
// func (d *v4Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
// 	ipAddr, err := net.ResolveIPAddr(addr.Network(), addr.String())
// 	if err != nil {
// 		return 0, err
// 	}
//
// 	header := &ipv4.Header{
// 		Version:  ipv4.Version,
// 		Len:      ipv4.HeaderLen,
// 		Protocol: 1,
// 		TotalLen: ipv4.HeaderLen + len(b),
// 		TTL:      64,
// 		Dst:      ipAddr.IP,
// 		Src:      d.src,
// 	}
//
// 	if d.df {
// 		header.Flags |= ipv4.DontFragment
// 	}
//
// 	return len(b), d.c.WriteTo(header, b, nil)
// }
//
// func (d *v4Conn) Close() error {
// 	return d.c.Close()
// }
//
// func (d *v4Conn) LocalAddr() net.Addr {
// 	return nil
// }
//
// func (d *v4Conn) SetDeadline(t time.Time) error {
// 	return d.c.SetDeadline(t)
// }
//
// func (d *v4Conn) SetReadDeadline(t time.Time) error {
// 	return d.c.SetReadDeadline(t)
// }
//
// func (d *v4Conn) SetWriteDeadline(t time.Time) error {
// 	return d.c.SetWriteDeadline(t)
// }
