package util

import (
	"fmt"
	"os"
	"runtime"
	"strconv"

	"github.com/vishvananda/netns"
)

func DoInNetworkNamespace(pid uint32, do func() error) error {
	var netnsPath string
	for _, p := range []string{
		fmt.Sprintf("/proc/%s/ns/net", strconv.FormatUint(uint64(pid), 10)),
	} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		netnsPath = p
	}

	if netnsPath == "" {
		return fmt.Errorf("no netns path available")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	return func() error {
		origin, err := netns.Get()
		if err != nil {
			return err
		}
		defer func() { _ = origin.Close() }()

		return func() error {
			targetNS, err := netns.GetFromPath(netnsPath)
			if err != nil {
				return err
			}
			defer func() { _ = targetNS.Close() }()

			return func() error {
				// enter target ns
				err = netns.Set(targetNS)
				if err != nil {
					return err
				}

				defer func() {
					err2 := netns.Set(origin)
					if err2 != nil {
						panic(fmt.Sprintf("unable to go back to original netns: %v", err2))
					}
				}()

				return do()
			}()
		}()
	}()
}
