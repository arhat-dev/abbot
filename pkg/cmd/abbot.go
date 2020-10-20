/*
Copyright 2020 The arhat.dev Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"

	"arhat.dev/abbot-proto/abbotgopb"
	"arhat.dev/pkg/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"arhat.dev/abbot/pkg/conf"
	"arhat.dev/abbot/pkg/constant"
	"arhat.dev/abbot/pkg/container"
	"arhat.dev/abbot/pkg/host"
)

func NewAbbotCmd() *cobra.Command {
	var (
		appCtx       context.Context
		configFile   string
		config       = new(conf.AbbotConfig)
		cliLogConfig = new(log.Config)
	)

	abbotCmd := &cobra.Command{
		Use:           "abbot",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Use == "version" {
				return nil
			}

			var err error
			appCtx, err = conf.ReadConfig(cmd, &configFile, cliLogConfig, config)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(appCtx, config)
		},
	}

	flags := abbotCmd.PersistentFlags()
	// config file
	flags.StringVarP(&configFile, "config", "c", constant.DefaultAbbotConfigFile, "path to the abbot config file")
	// log config options
	flags.AddFlagSet(log.FlagsForLogConfig("log.", cliLogConfig))
	// listen address
	flags.StringVar(&config.Abbot.Listen, "listen", constant.DefaultAbbotListenAddr, "set abbot listen address")

	// network manager config options
	flags.StringVar(
		&config.ContainerNetwork.DataDir,
		"ctr.dataDir",
		constant.DefaultContainerNetworkDataDir,
		"set data dir for container network",
	)
	// cni plugin
	flags.StringSliceVar(
		&config.ContainerNetwork.CNIPluginsLookupPaths,
		"ctr.cniLookupPath",
		[]string{constant.DefaultCNIPluginsDir},
		"set paths can find cni plugins",
	)

	abbotCmd.AddCommand(newRequestCmd(&appCtx))

	return abbotCmd
}

func run(ctx context.Context, config *conf.AbbotConfig) error {
	errCh := make(chan error)
	var netMgrServer *grpc.Server
	if config.Abbot.Listen == "" {
		u, err := url.Parse(config.Abbot.Listen)
		if err != nil {
			return err
		}

		addr := u.Host
		if u.Scheme == "unix" {
			addr = u.Path
			// clean up previous unix socket file
			if err = os.Remove(addr); err != nil && !os.IsNotExist(err) {
				return err
			}
		}

		l, err := net.Listen(u.Scheme, addr)
		if err != nil {
			return err
		}

		netMgrServer = grpc.NewServer()

		go func() {
			select {
			case errCh <- netMgrServer.Serve(l):
			case <-ctx.Done():
			}
		}()

		defer func() {
			netMgrServer.Stop()
			l.Close()
			if u.Scheme == "unix" {
				_ = os.Remove(addr)
			}
		}()
	}

	if netMgrServer != nil {
		// container manager only accepts dynamic config, thus control endpoint is required
		containerMgr, err := container.NewManager(ctx, &config.ContainerNetwork)
		if err != nil {
			return err
		}

		abbotgopb.RegisterNetworkManagerServer(netMgrServer, containerMgr)
	}

	hostMgr, err := host.NewManager(ctx, &config.HostNetwork)
	if err != nil {
		return err
	}

	go func() {
		select {
		case errCh <- hostMgr.Start():
		case <-ctx.Done():
		}
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("failed to start network manager: %w", err)
		}
	case <-ctx.Done():
		return nil
	}

	return nil
}
