package usernet

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"arhat.dev/pkg/confhelper"
	"arhat.dev/pkg/log"
	"github.com/dgrijalva/jwt-go"
	"github.com/goiiot/libmqtt"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type MQTTOverlayConfig struct {
	Broker    string `json:"broker" yaml:"broker"`
	Variant   string `json:"variant" yaml:"variant"`
	Version   string `json:"version" yaml:"version"`
	Transport string `json:"transport" yaml:"transport"`

	// InboundTopic the topic for data from mqtt broker -> [usernet]
	InboundTopic string `json:"inboundTopic" yaml:"inboundTopic"`

	// OutboundTopic the topic for data from [usernet] -> mqtt broker
	OutboundTopic string `json:"outboundTopic" yaml:"outboundTopic"`

	ClientID  string `json:"clientID" yaml:"clientID"`
	Username  string `json:"username" yaml:"username"`
	Password  string `json:"password" yaml:"password"`
	Keepalive int32  `json:"keepalive" yaml:"keepalive"`

	TLS confhelper.TLSConfig `json:"tls" yaml:"tls"`
}

type MQTTConnectInfo struct {
	Username string
	Password string
	ClientID string

	InboundTopic       string
	OutboundTopic      string
	InboundTopicHandle string

	TLSConfig *tls.Config
}

func (c MQTTOverlayConfig) GetConnectInfo() (*MQTTConnectInfo, error) {
	result := new(MQTTConnectInfo)

	variant := strings.ToLower(c.Variant)
	switch variant {
	case "azure-iot-hub":
		deviceID := c.ClientID
		result.ClientID = deviceID

		propertyBag, err := url.ParseQuery(c.OutboundTopic)
		if err != nil {
			return nil, fmt.Errorf("failed to parse property bag: %w", err)
		}
		propertyBag["abbot_id"] = []string{deviceID}
		propertyBag["abbot"] = []string{""}

		// azure iot-hub topics
		result.OutboundTopic = fmt.Sprintf("devices/%s/messages/events/%s", deviceID, propertyBag.Encode())
		result.InboundTopic = fmt.Sprintf("devices/%s/messages/devicebound/#", deviceID)
		result.InboundTopicHandle = fmt.Sprintf("devices/%s/messages/devicebound/.*", deviceID)

		result.Username = fmt.Sprintf("%s/%s/?api-version=2018-06-30", c.Broker, deviceID)
		// Password is set to SAS token if not using mTLS
		result.Password = c.Password
	case "gcp-iot-core":
		if !c.TLS.Enabled || c.TLS.Key == "" {
			return nil, fmt.Errorf("no private key found")
		}

		if c.TLS.Cert != "" {
			return nil, fmt.Errorf("cert file must be empty")
		}

		result.ClientID = c.ClientID
		parts := strings.Split(c.ClientID, "/")
		if len(parts) != 8 {
			return nil, fmt.Errorf("expect 8 sections in client id but found %d", len(parts))
		}

		// second section is project id
		projectID := parts[1]
		claims := jwt.StandardClaims{
			Audience: projectID,
			IssuedAt: time.Now().Unix(),
			// valid for half a day (max value is 24 hr)
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		}

		keyBytes, err := ioutil.ReadFile(c.TLS.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}

		var (
			key        interface{}
			signMethod jwt.SigningMethod
		)

		block, _ := pem.Decode(keyBytes)
		switch block.Type {
		case "EC PRIVATE KEY":
			signMethod = jwt.SigningMethodES256
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			signMethod = jwt.SigningMethodRS256
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		default:
			return nil, fmt.Errorf("unsupported private key algorithm")
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		token := jwt.NewWithClaims(signMethod, claims)
		jwtToken, err := token.SignedString(key)
		if err != nil {
			return nil, fmt.Errorf("failed to sign jwt token: %w", err)
		}

		// last section is the device id
		deviceID := parts[7]
		result.OutboundTopic = fmt.Sprintf("/devices/%s/events", deviceID)
		if c.OutboundTopic != "" {
			result.OutboundTopic = fmt.Sprintf("/devices/%s/events/%s", deviceID, c.OutboundTopic)
		}
		result.InboundTopic = fmt.Sprintf("/devices/%s/commands/#", deviceID)
		result.InboundTopicHandle = fmt.Sprintf("/devices/%s/commands.*", deviceID)
		result.Password = jwtToken
	case "aws-iot-core":
		if !c.TLS.Enabled || c.TLS.Cert == "" || c.TLS.Key == "" {
			return nil, fmt.Errorf("tls cert key pair must be provided for aws-iot-core")
		}

		result.ClientID = c.ClientID
		result.InboundTopic, result.OutboundTopic = c.InboundTopic, c.OutboundTopic
		result.InboundTopicHandle = result.InboundTopic
	case "", "standard":
		result.Username = c.Username
		result.Password = c.Password
		result.ClientID = c.ClientID

		result.InboundTopic, result.OutboundTopic = c.InboundTopic, c.OutboundTopic
		result.InboundTopicHandle = result.InboundTopic
	default:
		return nil, fmt.Errorf("unsupported variant type")
	}

	var err error
	result.TLSConfig, err = c.TLS.GetTLSConfig(false)
	if err != nil {
		return nil, fmt.Errorf("failed to create client tls config: %w", err)
	}

	if variant == "aws-iot-core" {
		result.TLSConfig.NextProtos = []string{"x-amzn-mqtt-ca"}
	}

	return result, nil
}

func (c MQTTOverlayConfig) createOverlayDriver(logger log.Interface, ep *channel.Endpoint) (OverlayDriver, error) {
	var options []libmqtt.Option
	switch c.Version {
	case "5":
		options = append(options, libmqtt.WithVersion(libmqtt.V5, false))
	case "3.1.1", "":
		options = append(options, libmqtt.WithVersion(libmqtt.V311, false))
	default:
		return nil, fmt.Errorf("unsupported mqtt version: %s", c.Version)
	}

	switch c.Transport {
	case "websocket":
		options = append(options, libmqtt.WithWebSocketConnector(0, nil))
	case "tcp", "":
		options = append(options, libmqtt.WithTCPConnector(0))
	default:
		return nil, fmt.Errorf("unsupported transport method: %s", c.Transport)
	}

	connInfo, err := c.GetConnectInfo()
	if err != nil {
		return nil, fmt.Errorf("invalid config options for mqtt connect: %w", err)
	}

	if connInfo.TLSConfig != nil {
		options = append(options, libmqtt.WithCustomTLS(connInfo.TLSConfig))
	}

	keepalive := c.Keepalive
	if keepalive == 0 {
		// default to 60 seconds
		keepalive = 60
	}

	options = append(options, libmqtt.WithConnPacket(libmqtt.ConnPacket{
		Username:     connInfo.Username,
		Password:     connInfo.Password,
		ClientID:     connInfo.ClientID,
		Keepalive:    uint16(keepalive),
		CleanSession: true,

		//IsWill:       true,
		//WillTopic:    connInfo.WillPubTopic,
		//WillQos:      libmqtt.Qos1,
		//WillRetain:   connInfo.SupportRetain,
		//WillMessage:  willMsgBytes,
	}))

	options = append(options, libmqtt.WithKeepalive(uint16(keepalive), 1.2))

	client, err := libmqtt.NewClient(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create mqtt client: %w", err)
	}

	d := &MQTTOverlayDriver{
		logger: logger,
		client: client,

		ep: ep,

		brokerAddress:      c.Broker,
		inboundTopic:       connInfo.InboundTopic,
		inboundTopicHandle: connInfo.InboundTopicHandle,
		outboundTopic:      connInfo.OutboundTopic,

		netErrCh:  make(chan error),
		connErrCh: make(chan error),
		subErrCh:  make(chan error),

		exited: 0,
	}

	return d, nil
}

type MQTTOverlayDriver struct {
	logger log.Interface
	client libmqtt.Client

	ep *channel.Endpoint

	brokerAddress      string
	inboundTopic       string
	inboundTopicHandle string
	outboundTopic      string

	netErrCh  chan error
	connErrCh chan error
	subErrCh  chan error

	exited int32
}

func (d *MQTTOverlayDriver) Connect(stopSig <-chan struct{}) error {
	dialOpts := []libmqtt.Option{
		libmqtt.WithRouter(libmqtt.NewRegexRouter()),
		libmqtt.WithAutoReconnect(false),
		libmqtt.WithConnHandleFunc(d.handleConn(stopSig)),
		libmqtt.WithSubHandleFunc(d.handleSub(stopSig)),
		libmqtt.WithPubHandleFunc(d.handlePub),
		libmqtt.WithNetHandleFunc(d.handleNet),
	}

	err := d.client.ConnectServer(d.brokerAddress, dialOpts...)
	if err != nil {
		return err
	}

	select {
	case <-stopSig:
		return nil
	case err = <-d.netErrCh:
		if err != nil {
			return err
		}
	case err = <-d.connErrCh:
		if err != nil {
			return err
		}
	}

	d.client.HandleTopic(d.inboundTopic, d.handleInbound)
	d.client.Subscribe(&libmqtt.Topic{Name: d.inboundTopic, Qos: libmqtt.Qos0})

	select {
	case <-stopSig:
		return nil
	case err := <-d.subErrCh:
		if err != nil {
			return err
		}
	}

	select {
	case err := <-d.netErrCh:
		return err
	case <-stopSig:
		d.client.Destroy(true)
		return nil
	}
}

func (d *MQTTOverlayDriver) SendPacket(p []byte) {
	d.client.Publish(&libmqtt.PublishPacket{
		Payload:   p,
		TopicName: d.outboundTopic,
		Qos:       0,
	})
}

func (d *MQTTOverlayDriver) Close() error {
	d.client.Destroy(true)

	if atomic.CompareAndSwapInt32(&d.exited, 0, 1) {
		close(d.netErrCh)
	}

	return nil
}

func (d *MQTTOverlayDriver) handleNet(client libmqtt.Client, server string, err error) {
	if err != nil {
		d.logger.I("network error happened", log.String("server", server), log.Error(err))

		// exit client on network error
		if atomic.CompareAndSwapInt32(&d.exited, 0, 1) {
			d.netErrCh <- err
			close(d.netErrCh)
		}
	}
}

func (d *MQTTOverlayDriver) handleConn(dialExitSig <-chan struct{}) libmqtt.ConnHandleFunc {
	return func(client libmqtt.Client, server string, code byte, err error) {
		switch {
		case err != nil:
			select {
			case <-dialExitSig:
				return
			case d.connErrCh <- err:
				return
			}
		case code != libmqtt.CodeSuccess:
			select {
			case <-dialExitSig:
				return
			case d.connErrCh <- fmt.Errorf("rejected by mqtt broker, code: %d", code):
				return
			}
		default:
			// connected to broker
			select {
			case <-dialExitSig:
				return
			case d.connErrCh <- nil:
				return
			}
		}
	}
}

func (d *MQTTOverlayDriver) handleSub(dialExitSig <-chan struct{}) libmqtt.SubHandleFunc {
	return func(client libmqtt.Client, topics []*libmqtt.Topic, err error) {
		select {
		case <-dialExitSig:
			return
		case d.subErrCh <- err:
			return
		}
	}
}

func (d *MQTTOverlayDriver) handlePub(client libmqtt.Client, topic string, err error) {
	if err != nil {
		d.logger.I("failed to publish message", log.String("topic", topic), log.Error(err))
	}
}

func (d *MQTTOverlayDriver) handleInbound(client libmqtt.Client, topic string, qos libmqtt.QosLevel, packet []byte) {
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 0,
		Data:               buffer.NewViewFromBytes(packet).ToVectorisedView(),
	})

	dstAddr := pb.Network().DestinationAddress()
	if dstAddr == dstAddr.To4() {
		d.ep.InjectInbound(ipv4.ProtocolNumber, pb)
	} else {
		d.ep.InjectInbound(ipv6.ProtocolNumber, pb)
	}
}
