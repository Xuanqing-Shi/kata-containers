// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"path"
	"time"

	"github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/mount"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
)

func wait(s *service, c *container, execID string) (int32, error) {
	var execs *exec
	var err error

	processID := c.id

	if execID == "" {
		//wait until the io closed, then wait the container
		<-c.exitIOch
	} else {
		execs, err = c.getExec(execID)
		if err != nil {
			return exitCode255, err
		}
		<-execs.exitIOch
		//This wait could be triggered before exec start which
		//will get the exec's id, thus this assignment must after
		//the exec exit, to make sure it get the exec's id.
		processID = execs.id
	}

	ret, err := s.sandbox.WaitProcess(c.id, processID)
	if err != nil {
		shimLog.WithError(err).WithFields(logrus.Fields{
			"container": c.id,
			"pid":       processID,
		}).Error("Wait for process failed")
	}

	timeStamp := time.Now()

	s.mu.Lock()
	if execID == "" {
		// Take care of the use case where it is a sandbox.
		// Right after the container representing the sandbox has
		// been deleted, let's make sure we stop and delete the
		// sandbox.

		if c.cType.IsSandbox() {
			// cancel watcher
			if s.monitor != nil {
				s.monitor <- nil
			}
			if err = s.sandbox.Stop(true); err != nil {
				shimLog.WithField("sandbox", s.sandbox.ID()).Error("failed to stop sandbox")
			}

			if err = s.sandbox.Delete(); err != nil {
				shimLog.WithField("sandbox", s.sandbox.ID()).Error("failed to delete sandbox")
			}
		} else {
			if _, err = s.sandbox.StopContainer(c.id, false); err != nil {
				shimLog.WithError(err).WithField("container", c.id).Warn("stop container failed")
			}
		}
		c.status = task.StatusStopped
		c.exit = uint32(ret)
		c.exitTime = timeStamp

		c.exitCh <- uint32(ret)

	} else {
		execs.status = task.StatusStopped
		execs.exitCode = ret
		execs.exitTime = timeStamp

		execs.exitCh <- uint32(ret)
	}
	s.mu.Unlock()

	go cReap(s, int(ret), c.id, execID, timeStamp)

	return ret, nil
}

func watchSandbox(s *service) {
	if s.monitor == nil {
		return
	}
	err := <-s.monitor
	if err == nil {
		return
	}
	s.monitor = nil

	s.mu.Lock()
	defer s.mu.Unlock()
	// sandbox malfunctioning, cleanup as much as we can
	shimLog.WithError(err).Warn("sandbox stopped unexpectedly")
	err = s.sandbox.Stop(true)
	if err != nil {
		shimLog.WithError(err).Warn("stop sandbox failed")
	}
	err = s.sandbox.Delete()
	if err != nil {
		shimLog.WithError(err).Warn("delete sandbox failed")
	}

	for _, c := range s.containers {
		if !c.mounted {
			continue
		}
		rootfs := path.Join(c.bundle, "rootfs")
		shimLog.WithField("rootfs", rootfs).WithField("container", c.id).Debug("container umount rootfs")
		if err := mount.UnmountAll(rootfs, 0); err != nil {
			shimLog.WithError(err).Warn("failed to cleanup rootfs mount")
		}
	}

	// Existing container/exec will be cleaned up by its waiters.
	// No need to send async events here.
}

func watchOOMEvents(ctx context.Context, s *service) {
	if s.sandbox == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			containerID, err := s.sandbox.GetOOMEvent()
			if err != nil {
				shimLog.WithError(err).Warn("failed to get OOM event from sandbox")
				// If the GetOOMEvent call is not implemented, then the agent is most likely an older version,
				// stop attempting to get OOM events.
				// for rust agent, the response code is not found
				if isGRPCErrorCode(codes.NotFound, err) {
					return
				}
				continue
			}

			s.send(&events.TaskOOM{
				ContainerID: containerID,
			})
		}
	}
}
