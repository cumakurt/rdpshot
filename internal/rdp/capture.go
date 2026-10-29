package rdp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"image"
	"io"
	"net"
	"strconv"
	"time"

	"rdpshot/internal/credssp"
	"rdpshot/internal/model"
)

// Capture errors.
var (
	ErrCaptureUnsupported = errors.New("rdp: framebuffer capture unsupported on this endpoint")
	ErrCaptureNoBitmap    = errors.New("rdp: no bitmap updates received")
	ErrCaptureTimeout     = errors.New("rdp: framebuffer capture timed out")
)

// CaptureOptions tunes authenticated framebuffer capture.
type CaptureOptions struct {
	Timeout       time.Duration
	DesktopWidth  int
	DesktopHeight int
	// MinPainted is the fraction of non-black pixels required to accept the
	// frame (0 leaves the default of 0.02).
	MinPainted float64
	// MaxPDUs bounds how many MCS data indications are processed.
	MaxPDUs int
}

func (o CaptureOptions) withDefaults() CaptureOptions {
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.DesktopWidth <= 0 {
		o.DesktopWidth = 1024
	}
	if o.DesktopHeight <= 0 {
		o.DesktopHeight = 768
	}
	if o.MinPainted <= 0 {
		o.MinPainted = 0.02
	}
	if o.MaxPDUs <= 0 {
		o.MaxPDUs = 512
	}
	return o
}

// Capture opens an NLA RDP session with the given credentials, completes the
// connection sequence, and returns a framebuffer filled from slow-path bitmap
// updates. Servers that only speak RDPGFX/Orders will return ErrCaptureNoBitmap.
func Capture(ctx context.Context, ep model.Endpoint, cred model.Credential, opts CaptureOptions) (image.Image, error) {
	opts = opts.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	dialer := net.Dialer{Timeout: opts.Timeout}
	addr := net.JoinHostPort(ep.Address, strconv.Itoa(int(ep.Port)))
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCaptureUnsupported, err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(opts.Timeout))

	if err := WriteConnectionRequest(raw, "rdpshot", RequestedProtocols()); err != nil {
		return nil, err
	}
	neg, err := ReadConnectionConfirm(raw)
	if err != nil {
		return nil, err
	}
	if neg.FailureCode != nil || (neg.SelectedProtocol != ProtocolHybrid && neg.SelectedProtocol != ProtocolHybridEx) {
		return nil, fmt.Errorf("%w: NLA/Hybrid required for Go framebuffer", ErrCaptureUnsupported)
	}

	tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("rdp: TLS handshake: %w", err)
	}

	client := &credssp.Client{Version: 6}
	sess, err := client.HandshakeSession(ctx, tlsConn, cred.Username, cred.Secret, cred.Domain)
	if err != nil {
		return nil, fmt.Errorf("rdp: CredSSP session: %w", err)
	}
	conn := sess.Conn
	br := bufio.NewReader(conn)

	c := &captureClient{
		conn:   conn,
		br:     br,
		opts:   opts,
		fb:     NewFramebuffer(opts.DesktopWidth, opts.DesktopHeight),
		source: 1001,
		cache:  newBitmapCache(),
	}
	if err := c.runMCS(neg.SelectedProtocol); err != nil {
		return nil, err
	}
	if err := c.sendClientInfo(cred); err != nil {
		return nil, err
	}
	if err := c.loop(ctx); err != nil {
		if c.bitmaps > 0 && c.fb.PaintedFraction() >= opts.MinPainted {
			return c.fb.Img, nil
		}
		return nil, err
	}
	if c.bitmaps == 0 || c.fb.PaintedFraction() < opts.MinPainted {
		return nil, ErrCaptureNoBitmap
	}
	return c.fb.Img, nil
}

type captureClient struct {
	conn      net.Conn
	br        *bufio.Reader
	opts      CaptureOptions
	fb        *Framebuffer
	userID    uint16
	ioChannel uint16
	shareID   uint32
	source    uint16
	bitmaps   int
	orders    int
	active    bool
	cache     *bitmapCache
}

func (c *captureClient) runMCS(selectedProtocol uint32) error {
	gcc := BuildGCCClientData(selectedProtocol, nil)
	if err := writeDataTPDU(c.conn, BuildConnectInitial(gcc)); err != nil {
		return err
	}
	payload, err := readDataTPDU(c.br)
	if err != nil {
		return err
	}
	server, err := ParseConnectResponse(payload)
	if err != nil {
		return err
	}
	c.ioChannel = server.MCSChannelID
	if c.ioChannel == 0 {
		c.ioChannel = MCSGlobalChannel
	}

	if err := writeDataTPDU(c.conn, buildErectDomainRequest()); err != nil {
		return err
	}
	if err := writeDataTPDU(c.conn, buildAttachUserRequest()); err != nil {
		return err
	}
	payload, err = readDataTPDU(c.br)
	if err != nil {
		return err
	}
	attach, err := ParseMCSPDU(payload)
	if err != nil {
		return err
	}
	if attach.Type != mcsAttachUserConfirm || attach.Result != 0 {
		return fmt.Errorf("rdp: attach user failed (type=%d result=%d)", attach.Type, attach.Result)
	}
	c.userID = attach.UserID
	c.source = c.userID + MCSUserChannelBase

	for _, ch := range []uint16{c.userID + MCSUserChannelBase, c.ioChannel} {
		if err := writeDataTPDU(c.conn, buildChannelJoinRequest(c.userID, ch)); err != nil {
			return err
		}
		payload, err = readDataTPDU(c.br)
		if err != nil {
			return err
		}
		join, err := ParseMCSPDU(payload)
		if err != nil {
			return err
		}
		if join.Type == mcsChannelJoinConfirm && join.Result != 0 {
			return fmt.Errorf("rdp: channel join %d failed", ch)
		}
	}
	return nil
}

func (c *captureClient) sendClientInfo(cred model.Credential) error {
	info := buildClientInfoPDU(cred.Domain, cred.Username, cred.Secret)
	return writeDataTPDU(c.conn, buildSendDataRequest(c.userID, c.ioChannel, info))
}

func (c *captureClient) sendMCS(payload []byte) error {
	return writeDataTPDU(c.conn, buildSendDataRequest(c.userID, c.ioChannel, payload))
}

func (c *captureClient) loop(ctx context.Context) error {
	for i := 0; i < c.opts.MaxPDUs; i++ {
		if err := ctx.Err(); err != nil {
			if c.bitmaps+c.orders > 0 {
				return nil
			}
			return fmt.Errorf("%w: %v", ErrCaptureTimeout, err)
		}
		fast, payload, err := readCaptureFrame(c.br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ErrDisconnected) {
				if c.bitmaps+c.orders > 0 {
					return nil
				}
			}
			return err
		}
		if fast {
			b, o, _ := c.fb.applyFastPathUpdates(payload, c.cache)
			c.bitmaps += b
			c.orders += o
			if c.active && c.bitmaps+c.orders > 0 && c.fb.PaintedFraction() >= c.opts.MinPainted {
				return nil
			}
			continue
		}
		pdu, err := ParseMCSPDU(payload)
		if err != nil {
			continue
		}
		if pdu.Type == mcsDisconnectProvider {
			if c.bitmaps > 0 {
				return nil
			}
			return ErrDisconnected
		}
		if pdu.Type != mcsSendDataIndication || len(pdu.Payload) == 0 {
			continue
		}
		if err := c.handleUserData(pdu.Payload); err != nil {
			return err
		}
		if c.active && c.bitmaps+c.orders > 0 && c.fb.PaintedFraction() >= c.opts.MinPainted {
			if c.bitmaps+c.orders >= 3 {
				return nil
			}
		}
	}
	if c.bitmaps+c.orders > 0 {
		return nil
	}
	return ErrCaptureNoBitmap
}

func (c *captureClient) handleUserData(data []byte) error {
	if isLicensePDU(data) {
		return c.sendMCS(buildLicenseErrorValidClient())
	}
	if len(data) < 6 {
		return nil
	}
	_, pduType, _, err := parseShareControlHeader(data)
	if err != nil {
		return nil
	}
	switch pduType {
	case pduTypeDemandActive:
		return c.onDemandActive(data)
	case pduTypeData:
		return c.onDataPDU(data)
	case pduTypeDeactivateAll:
		c.active = false
	}
	return nil
}

func (c *captureClient) onDemandActive(data []byte) error {
	if len(data) < 10 {
		return fmt.Errorf("rdp: short demand active")
	}
	c.shareID = binaryLE32(data[6:10])
	confirm := buildConfirmActivePDU(c.shareID, c.source,
		uint16(c.opts.DesktopWidth), uint16(c.opts.DesktopHeight))
	if err := c.sendMCS(confirm); err != nil {
		return err
	}
	for _, pdu := range [][]byte{
		buildSynchronizePDU(c.shareID, c.source),
		buildControlPDU(c.shareID, c.source, ctrlActionCooperate),
		buildControlPDU(c.shareID, c.source, ctrlActionRequestControl),
		buildFontListPDU(c.shareID, c.source),
	} {
		if err := c.sendMCS(pdu); err != nil {
			return err
		}
	}
	c.active = true
	return nil
}

func (c *captureClient) onDataPDU(data []byte) error {
	if len(data) < 18 {
		return nil
	}
	_, pduType2, payload, err := parseShareDataHeader(data[6:])
	if err != nil {
		return nil
	}
	switch pduType2 {
	case pduType2Update:
		if len(payload) < 2 {
			return nil
		}
		updateType := binaryLE16(payload[0:2])
		if updateType != updateTypeBitmap {
			return nil
		}
		n, err := c.fb.ApplyBitmapUpdate(payload[2:])
		if err != nil {
			return nil
		}
		c.bitmaps += n
	case pduType2SetError:
		if len(payload) >= 4 {
			code := binaryLE32(payload[0:4])
			return fmt.Errorf("rdp: server set error info 0x%08x", code)
		}
	}
	return nil
}

func binaryLE16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

func binaryLE32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
