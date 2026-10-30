package rdp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"rdpshot/internal/model"
)

// ErrNotRDP is returned when the target does not speak the RDP protocol.
var ErrNotRDP = errors.New("rdp: service did not speak the RDP protocol")

// Options tunes a reconnaissance connection.
type Options struct {
	// Timeout bounds each protocol exchange.
	Timeout time.Duration
	// Cookie is the optional mstshash value sent in the connection request.
	Cookie string
	// ProbeBlueKeep runs the safe MS_T120 detection probe when possible.
	ProbeBlueKeep bool
	// ProbeTimeout bounds the observation window of the detection probe.
	ProbeTimeout time.Duration
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.ProbeTimeout <= 0 {
		o.ProbeTimeout = 6 * time.Second
	}
	if o.Cookie == "" {
		o.Cookie = "rdpshot"
	}
	return o
}

// BlueKeepResult is the outcome of the safe CVE-2019-0708 detection probe.
type BlueKeepResult struct {
	// Attempted reports whether the probe could be executed at all. It is
	// false when NLA or legacy encryption prevented reaching the channel layer.
	Attempted bool
	// Triggered reports that the server answered the benign MS_T120 channel
	// messages with a Disconnect Provider Ultimatum, which is what unpatched
	// servers do (the same signal used by rdpscan's safe check).
	Triggered bool
	// Reason is a short human readable explanation of the outcome.
	Reason string
	// Evidence holds protocol level details for the report.
	Evidence string
}

// GatherResult bundles everything collected from one endpoint.
type GatherResult struct {
	Service  model.ServiceInfo
	BlueKeep *BlueKeepResult
}

type session struct {
	conn       net.Conn
	br         *bufio.Reader
	opts       Options
	svc        *model.ServiceInfo
	neg        NegotiationResult
	server     ServerData
	userID     uint16
	msT120Chan uint16
	// channelDataAllowed is true when virtual channel payloads can be sent
	// without implementing legacy RDP standard security keys.
	channelDataAllowed bool
	stageErrors        []string
}

// Gather connects to one endpoint, records the RDP service fingerprint and,
// when enabled and possible, runs the safe BlueKeep detection probe.
//
// Partial results are returned alongside a nil error once the RDP negotiation
// succeeded: later stage failures (TLS, MCS) are recorded as evidence so the
// caller still learns about the service.
func Gather(ctx context.Context, ep model.Endpoint, opts Options) (GatherResult, error) {
	var result GatherResult
	result.Service.Evidence = map[string]string{}
	opts = opts.withDefaults()

	dialer := net.Dialer{Timeout: opts.Timeout}
	addr := net.JoinHostPort(ep.Address, strconv.Itoa(int(ep.Port)))
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return result, classifyDialError(err)
	}
	defer conn.Close()

	s := &session{
		conn: conn,
		br:   bufio.NewReader(conn),
		opts: opts,
		svc:  &result.Service,
	}

	if err := s.negotiate(); err != nil {
		return result, err
	}
	if s.neg.Failed() {
		// The server rejected the requested protocols but still spoke RDP.
		return result, nil
	}

	if err := s.setupSecurityLayer(ctx); err != nil {
		s.fail("security_layer", err)
		return result, nil
	}
	if s.neg.NLARequired() {
		// CredSSP would be required to reach the MCS layer; recon stops here.
		return result, nil
	}
	if err := s.connectMCS(); err != nil {
		s.fail("mcs_connect", err)
		return result, nil
	}
	if s.channelDataAllowed {
		if err := s.joinChannels(); err != nil {
			s.fail("mcs_channel_join", err)
			return result, nil
		}
	}
	if opts.ProbeBlueKeep {
		result.BlueKeep = s.probeMS_T120()
	}
	return result, nil
}

// negotiate performs the X.224 connection and RDP protocol negotiation.
func (s *session) negotiate() error {
	if err := s.setDeadline(); err != nil {
		return err
	}
	if err := WriteConnectionRequest(s.conn, s.opts.Cookie, RequestedProtocols()); err != nil {
		return err
	}
	res, err := ReadConnectionConfirm(s.br)
	if err != nil {
		if errors.Is(err, ErrNotRDP) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrNotRDP, err)
	}
	s.neg = res
	s.svc.NegotiatedProtocol = res.SelectedProtocol
	s.svc.NegotiationFailureCode = res.FailureCode
	s.svc.NLARequired = res.NLARequired() ||
		(res.FailureCode != nil && *res.FailureCode == FailureHybridRequiredByServer)
	s.svc.Evidence["x224_negotiation"] = hex.EncodeToString(res.Raw)
	if res.FailureCode != nil {
		s.svc.Evidence["negotiation_failure"] = FailureCodeText(*res.FailureCode)
	} else {
		s.svc.Evidence["negotiated_protocol"] = ProtocolName(res.SelectedProtocol)
	}
	return nil
}

// setupSecurityLayer upgrades to TLS when the server selected it and records
// the certificate details.
func (s *session) setupSecurityLayer(ctx context.Context) error {
	if s.neg.SelectedProtocol != ProtocolSSL && s.neg.SelectedProtocol != ProtocolHybrid &&
		s.neg.SelectedProtocol != ProtocolHybridEx {
		return nil
	}
	if err := s.setDeadline(); err != nil {
		return err
	}
	// Certificate trust is irrelevant for a scanner; the certificate is
	// captured and reported instead of being validated against a CA.
	tlsConn := tls.Client(s.conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // documented above
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("rdp: TLS handshake: %w", err)
	}
	s.conn = tlsConn
	s.br = bufio.NewReader(tlsConn)
	state := tlsConn.ConnectionState()
	DescribeTLS(s.svc, &state)
	return nil
}

// connectMCS sends the MCS Connect Initial and records the server data.
func (s *session) connectMCS() error {
	channels := []ChannelDef{{
		Name:    "MS_T120",
		Options: channelOptionInitialized | channelOptionCompressRDP,
		ID:      firstStaticChannelID,
	}}
	s.msT120Chan = firstStaticChannelID

	gcc := BuildGCCClientData(RequestedProtocols(), channels)
	if err := s.setDeadline(); err != nil {
		return err
	}
	if err := writeDataTPDU(s.conn, BuildConnectInitial(gcc)); err != nil {
		return err
	}
	payload, err := readDataTPDU(s.br)
	if err != nil {
		return err
	}
	server, err := ParseConnectResponse(payload)
	if err != nil {
		return err
	}
	s.server = server

	s.svc.ServerVersion = server.Version
	s.svc.EncryptionMethods = server.EncryptionMethod
	s.svc.EncryptionLevel = EncryptionLevelName(server.EncryptionLevel)
	s.svc.MCSChannelIDs = server.ChannelIDs
	s.svc.Evidence["mcs_channel_id"] = strconv.Itoa(int(server.MCSChannelID))
	s.svc.Evidence["server_core_version"] = fmt.Sprintf("0x%08x", server.Version)
	for key, value := range server.Raw {
		s.svc.Evidence[key] = value
	}
	s.svc.OSGuess = guessOS(server.Version)

	// Channel payloads can be exchanged without legacy keys when the session
	// runs inside TLS or the server asked for no RDP level encryption.
	s.channelDataAllowed = s.neg.SelectedProtocol == ProtocolSSL ||
		(s.neg.SelectedProtocol == ProtocolRDP && server.EncryptionLevel == 0)
	if !s.channelDataAllowed {
		s.svc.Evidence["channel_data"] =
			"legacy RDP encryption required; virtual channel probing not supported in this version"
	}
	return nil
}

// joinChannels performs the MCS domain setup used before channel probing.
func (s *session) joinChannels() error {
	steps := []struct {
		name string
		pdu  []byte
	}{
		{"erect_domain", buildErectDomainRequest()},
		{"attach_user", buildAttachUserRequest()},
	}
	for _, step := range steps {
		if err := s.setDeadline(); err != nil {
			return err
		}
		if err := writeDataTPDU(s.conn, step.pdu); err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
		if step.name != "erect_domain" {
			payload, err := readDataTPDU(s.br)
			if err != nil {
				return fmt.Errorf("%s: %w", step.name, err)
			}
			pdu, err := ParseMCSPDU(payload)
			if err != nil {
				return fmt.Errorf("%s: %w", step.name, err)
			}
			if pdu.Type != mcsAttachUserConfirm || pdu.Result != 0 {
				return fmt.Errorf("%s: unexpected MCS response type %d result %d", step.name, pdu.Type, pdu.Result)
			}
			s.userID = pdu.UserID
		}
	}

	join := []uint16{s.userID + MCSUserChannelBase, MCSGlobalChannel, s.msT120Chan}
	for _, channel := range join {
		if err := s.setDeadline(); err != nil {
			return err
		}
		if err := writeDataTPDU(s.conn, buildChannelJoinRequest(s.userID, channel)); err != nil {
			return fmt.Errorf("channel_join %d: %w", channel, err)
		}
		payload, err := readDataTPDU(s.br)
		if err != nil {
			return fmt.Errorf("channel_join %d: %w", channel, err)
		}
		pdu, err := ParseMCSPDU(payload)
		if err != nil {
			return fmt.Errorf("channel_join %d: %w", channel, err)
		}
		if pdu.Type != mcsChannelJoinConfirm || pdu.Result != 0 {
			return fmt.Errorf("channel_join %d: unexpected MCS response type %d result %d", channel, pdu.Type, pdu.Result)
		}
	}
	s.svc.Evidence["mcs_user_id"] = strconv.Itoa(int(s.userID))
	return nil
}

// probeMS_T120 runs the safe CVE-2019-0708 detection probe: two benign channel
// messages are sent on the MS_T120 channel and the observation window watches
// for a Disconnect Provider Ultimatum. No exploit payload is involved.
func (s *session) probeMS_T120() *BlueKeepResult {
	result := &BlueKeepResult{Attempted: true}
	if !s.channelDataAllowed {
		result.Attempted = false
		result.Reason = "virtual channel layer unavailable (NLA or legacy encryption)"
		return result
	}

	payloads := buildMS_T120CheckPayloads()
	sent := 0
sendLoop:
	for i := 0; i < 5; i++ {
		for _, payload := range payloads {
			channelPDU := buildChannelPDU(payload)
			// The basic security header is present while no license has been
			// issued, mirroring common RDP client behaviour.
			secured := append([]byte{0, 0, 0, 0}, channelPDU...)
			if err := s.setDeadline(); err != nil {
				break sendLoop
			}
			if err := writeDataTPDU(s.conn, buildSendDataRequest(s.userID, s.msT120Chan, secured)); err != nil {
				// A send failure can simply mean the server already reacted;
				// fall through to the observation window when anything was sent.
				break sendLoop
			}
			sent++
		}
	}
	if sent < len(payloads) {
		result.Reason = "probe send failed before a full MS_T120 check pair was delivered"
		return result
	}
	result.Evidence = fmt.Sprintf("sent %d MS_T120 check messages (sizes 0x%x and 0x%x) on channel %d",
		sent, len(payloads[0]), len(payloads[1]), s.msT120Chan)

	deadline := time.Now().Add(s.opts.ProbeTimeout)
	for {
		if err := s.conn.SetDeadline(deadline); err != nil {
			result.Reason = "probe read failed"
			return result
		}
		payload, err := readDataTPDU(s.br)
		if err != nil {
			switch {
			case errors.Is(err, ErrDisconnected):
				// A bare TCP close is not a confirmed BlueKeep signal.
				result.Reason = "server closed the connection after the check messages"
			case isTimeout(err):
				result.Reason = fmt.Sprintf("no MS_T120 response within %s", s.opts.ProbeTimeout)
			default:
				result.Reason = "probe read failed"
				result.Evidence = strings.TrimSpace(result.Evidence + "; " + err.Error())
			}
			return result
		}
		pdu, err := ParseMCSPDU(payload)
		if err != nil {
			continue
		}
		// Only an MCS Disconnect Provider Ultimatum after a full check pair is
		// treated as a confirmed vulnerable signal.
		if pdu.Type == mcsDisconnectProvider {
			result.Triggered = true
			result.Reason = "server answered the MS_T120 check with a Disconnect Provider Ultimatum"
			result.Evidence = strings.TrimSpace(result.Evidence +
				fmt.Sprintf("; MCS Disconnect Provider Ultimatum (reason %#x)", pdu.Result))
			return result
		}
	}
}

// ServiceInfo is a convenience accessor used by tests.
func (s *session) serviceInfo() model.ServiceInfo { return *s.svc }

func (s *session) setDeadline() error {
	return s.conn.SetDeadline(time.Now().Add(s.opts.Timeout))
}

func (s *session) fail(stage string, err error) {
	s.svc.Evidence[stage+"_error"] = err.Error()
}

// guessOS produces a conservative guess from the server core version. It is
// deliberately vague: the version field alone does not identify a Windows build.
func guessOS(version uint32) string {
	if version == 0 {
		return ""
	}
	major := version & 0xffff
	switch {
	case major >= 8:
		return "Windows (modern RDP service)"
	case major >= 5:
		return "Windows (legacy RDP 5.x/6.x service)"
	default:
		return "Windows (legacy RDP service)"
	}
}

func classifyDialError(err error) error {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded), isTimeout(err):
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	}
	return fmt.Errorf("%w: %v", ErrNetwork, err)
}

// ErrTimeout and ErrNetwork classify transport level failures for callers.
var (
	ErrTimeout = errors.New("rdp: timeout")
	ErrNetwork = errors.New("rdp: network error")
)

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
