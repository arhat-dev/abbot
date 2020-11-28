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
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"arhat.dev/abbot-proto/abbotgopb"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"arhat.dev/abbot/pkg/conf"
	"arhat.dev/abbot/pkg/constant"
)

func newProcessCmd(appCtx *context.Context) *cobra.Command {
	reqCmd := &cobra.Command{
		Use:           "process",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runProcess(*appCtx, (*appCtx).Value(constant.ContextKeyConfig).(*conf.AbbotConfig))
			if err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err.Error())
			}

			return nil
		},
	}

	return reqCmd
}

// nolint:gocyclo
func runProcess(ctx context.Context, config *conf.AbbotConfig) error {
	pbBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read request data: %w", err)
	}

	req := new(abbotgopb.Request)
	expectEnvAction := false

	if len(pbBytes) != 0 {
		expectEnvAction = true
		err = req.Unmarshal(pbBytes)
		if err != nil {
			return fmt.Errorf("failed to unmarshal pb bytes: %w", err)
		}
	}

	reqAction, hasEnvAction := os.LookupEnv("ABBOT_REQ_ACTION")
	if hasEnvAction {
		switch reqAction {
		case "container:restore":
			req.Kind = abbotgopb.REQ_RESTORE_CTR_NETWORK
		case "container:query":
			req.Kind = abbotgopb.REQ_QUERY_CTR_NETWORK
		case "container:delete":
			req.Kind = abbotgopb.REQ_DELETE_CTR_NETWORK
		case "host:query":
			req.Kind = abbotgopb.REQ_QUERY_HOST_NETWORK_CONFIG
		default:
			return fmt.Errorf("unsupported env action")
		}
	} else if expectEnvAction {
		return fmt.Errorf("invalid request with no request body and env action")
	}

	// override host network requests
	{
		// nolint:gocritic
		switch req.Kind {
		case abbotgopb.REQ_QUERY_HOST_NETWORK_CONFIG:
			reqBody := new(abbotgopb.HostNetworkConfigQueryRequest)
			if len(req.Body) != 0 {
				err = reqBody.Unmarshal(req.Body)
				if err != nil {
					return fmt.Errorf("failed to unmarshal HostNetworkConfigQueryRequest: %w", err)
				}
			}

			providers := strings.Split(os.Getenv("ABBOT_REQ_HOST_PROVIDER"), ";")
			for _, p := range providers {
				if len(p) == 0 {
					continue
				}

				reqBody.Providers = append(reqBody.Providers, p)
			}

			req.Body, err = reqBody.Marshal()
		}
		if err != nil {
			return fmt.Errorf("failed to override host network request: %w", err)
		}
	}

	// override container network requests (id and pid)
	{
		ctrID := os.Getenv("ABBOT_REQ_CONTAINER_ID")
		ctrPIDStr := os.Getenv("ABBOT_REQ_CONTAINER_PID")
		pid := int64(-1)
		if len(ctrPIDStr) != 0 {
			pid, err = strconv.ParseInt(ctrPIDStr, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid container pid override %q: %w", ctrPIDStr, err)
			}
			if pid < 0 {
				return fmt.Errorf("invalid negative container pid: %q", ctrPIDStr)
			}
		}

		// has override
		if len(ctrID) != 0 || pid != 0 {
			switch req.Kind {
			case abbotgopb.REQ_ENSURE_CTR_NETWORK:
				reqBody := new(abbotgopb.ContainerNetworkEnsureRequest)
				// container ensure request must provide request body, or it's invalid
				err = reqBody.Unmarshal(req.Body)
				if err != nil {
					return fmt.Errorf("failed to unmarshal ContainerNetworkEnsureRequest: %w", err)
				}

				if len(ctrID) != 0 {
					reqBody.ContainerId = ctrID
					if len(reqBody.CniArgs) > 0 {
						if v, ok := reqBody.CniArgs["K8S_POD_INFRA_CONTAINER_ID"]; ok && v == "" {
							reqBody.CniArgs["K8S_POD_INFRA_CONTAINER_ID"] = ctrID
						}
					}
				}
				if pid > 0 {
					reqBody.Pid = uint32(pid)
				}
				req.Body, err = reqBody.Marshal()
			case abbotgopb.REQ_RESTORE_CTR_NETWORK:
				reqBody := new(abbotgopb.ContainerNetworkRestoreRequest)
				if len(req.Body) != 0 {
					err = reqBody.Unmarshal(req.Body)
					if err != nil {
						return fmt.Errorf("failed to unmarshal ContainerNetworkRestoreRequest: %w", err)
					}
				}

				if len(ctrID) != 0 {
					reqBody.ContainerId = ctrID
				}
				if pid != 0 {
					reqBody.Pid = uint32(pid)
				}

				req.Body, err = reqBody.Marshal()
			case abbotgopb.REQ_DELETE_CTR_NETWORK:
				reqBody := new(abbotgopb.ContainerNetworkDeleteRequest)
				if len(req.Body) != 0 {
					err = reqBody.Unmarshal(req.Body)
					if err != nil {
						return fmt.Errorf("failed to unmarshal ContainerNetworkDeleteRequest: %w", err)
					}
				}

				if len(ctrID) != 0 {
					reqBody.ContainerId = ctrID
				}
				if pid > 0 {
					reqBody.Pid = uint32(pid)
				}

				req.Body, err = reqBody.Marshal()
			case abbotgopb.REQ_QUERY_CTR_NETWORK:
				reqBody := new(abbotgopb.ContainerNetworkQueryRequest)
				if len(req.Body) != 0 {
					err = reqBody.Unmarshal(req.Body)
					if err != nil {
						return fmt.Errorf("failed to unmarshal ContainerNetworkQueryRequest: %w", err)
					}
				}

				if len(ctrID) != 0 {
					reqBody.ContainerId = ctrID
				}
				if pid > 0 {
					reqBody.Pid = uint32(pid)
				}

				req.Body, err = reqBody.Marshal()
			}
			if err != nil {
				return fmt.Errorf("failed to override container network request: %w", err)
			}
		}
	}

	conn, err := grpc.Dial(config.Abbot.Listen, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to dial abbot: %w", err)
	}

	client := abbotgopb.NewNetworkManagerClient(conn)
	resp, err := client.Process(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to process request: %w", err)
	}

	respBytes, err := resp.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	_, err = fmt.Fprintln(os.Stdout, respBytes)
	if err != nil {
		return fmt.Errorf("failed to write response to stdout: %w", err)
	}

	return nil
}
