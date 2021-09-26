// Copyright (c) 2021 Alibaba Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"

	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/runtime/v2/shim"
	"github.com/containerd/containerd/runtime/v2/task"
	"github.com/containerd/ttrpc"
	"github.com/pkg/errors"
)

func init() {
	plugin.Register(&plugin.Registration{
		Type:     plugin.TTRPCPlugin,
		ID:       "image",
		Requires: []plugin.Type{"*"},
		InitFn:   initImageService,
	})
}

type ImageService struct {
	s *service
}

func initImageService(ic *plugin.InitContext) (interface{}, error) {
	i, err := ic.GetByID(plugin.TTRPCPlugin, "task")
	if err != nil {
		return nil, errors.Errorf("get task plugin error. %v")
	}
	task := i.(*shim.TaskService)
	s := task.Local.(*service)
	is := &ImageService{s: s}
	return is, nil
}

func (is *ImageService) RegisterTTRPC(server *ttrpc.Server) error {
	task.RegisterImageService(server, is)
	return nil
}

func (is *ImageService) PullImage(ctx context.Context, req *task.PullImageRequest) (resp *task.PullImageResponse, err error) {
	shimLog.Debugf("kata runtime PullImage: %v", req)

	resp, err = is.s.sandbox.PullImage(ctx, req)
	shimLog.Debugf("kata runtime PullImage: %v, %v", resp, err)
	return
}
