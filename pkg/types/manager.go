package types

import "arhat.dev/abbot-proto/abbotgopb"

type Manager interface {
	abbotgopb.NetworkManagerServer
}
