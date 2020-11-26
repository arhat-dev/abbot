package usernet

type OverlayDriver interface {
	// Connect establish a connection to remote endpoint, and leave it as is, no reconnection will be
	// performed internally
	// this function call will block until failed (connection lost) or context canceled
	Connect(stopCh <-chan struct{}) error

	// WritePacket send L3 packet to overlay network
	SendPacket(p []byte)

	// Close this overlay driver
	Close() error
}
