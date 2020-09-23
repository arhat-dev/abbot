/*
Copyright 2019 The arhat.dev Authors.

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
	"encoding/base64"
	"fmt"
	"os"

	"arhat.dev/abbot-proto/abbotgopb"

	"arhat.dev/pkg/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"arhat.dev/abbot/pkg/conf"
	"arhat.dev/abbot/pkg/constant"
)

func newRequestCmd(appCtx *context.Context) *cobra.Command {
	reqCmd := &cobra.Command{
		Use:           "request",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pbBytes, err := base64.StdEncoding.DecodeString(args[0])
			if err != nil {
				return fmt.Errorf("failed to decode base64 encoded request: %w", err)
			}

			req := new(abbotgopb.Request)
			err = req.Unmarshal(pbBytes)
			if err != nil {
				return fmt.Errorf("failed to unmarshal pb bytes: %w", err)
			}

			return runRequest(*appCtx, (*appCtx).Value(constant.ContextKeyConfig).(*conf.AbbotConfig), req)
		},
	}

	return reqCmd
}

func runRequest(ctx context.Context, config *conf.AbbotConfig, req *abbotgopb.Request) error {
	logger := log.Log.WithName("request")

	conn, err := grpc.Dial(config.Abbot.Listen, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		logger.I("failed to dial network manager", log.Error(err))
		return err
	}

	client := abbotgopb.NewNetworkManagerClient(conn)
	resp, err := client.Process(ctx, req)
	if err != nil {
		logger.I("failed to process request", log.Error(err))
		return err
	}

	respBytes, err := resp.Marshal()
	if err != nil {
		logger.I("failed to marshal response", log.Error(err))
		return err
	}

	_, err = fmt.Fprintln(os.Stdout, base64.StdEncoding.EncodeToString(respBytes))
	if err != nil {
		logger.I("failed to write response to stdout", log.Error(err))
		return err
	}

	return nil
}
