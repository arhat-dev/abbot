package util

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"arhat.dev/abbot/pkg/wrap/netlink"
)

func TestGetAddressesToAddAndToDelete(t *testing.T) {
	expected := make(map[string]*netlink.Addr)
	actual := make(map[string]*netlink.Addr)

	add := "192.168.0.1/24"
	del := "172.16.0.1/24"
	expectedAddrs := []string{
		"10.0.0.1/24", add,
	}
	actualAddrs := []string{
		"10.0.0.1/24", del,
	}

	var err error
	for _, addr := range expectedAddrs {
		expected[addr], err = netlink.ParseAddr(addr)

		assert.NoError(t, err)
	}

	for _, addr := range actualAddrs {
		actual[addr], err = netlink.ParseAddr(addr)

		assert.NoError(t, err)
	}

	toAdd, toDel := GetIPsToAddAndToDelete(actual, expected)
	assert.Len(t, toAdd, 1)
	assert.Len(t, toDel, 1)

	for k := range toAdd {
		assert.EqualValues(t, add, k)
	}

	for k := range toDel {
		assert.EqualValues(t, del, k)
	}

	assert.Len(t, actual, 1)
	assert.Len(t, expected, 2)
}
