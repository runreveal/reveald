package command

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/runreveal/kawa"
	"github.com/runreveal/reveald/internal/types"
)

type Option func(*Command)

func WithCmd(cmd string) Option {
	return func(c *Command) {
		c.cmd = cmd
	}
}

func WithEnvironment(env map[string]string) Option {
	return func(c *Command) {
		c.environ = env
	}
}

func WithInheritEnv(in bool) Option {
	return func(c *Command) {
		c.inheritEnv = in
	}
}

func WithInterval(interval time.Duration) Option {
	return func(c *Command) {
		c.interval = interval
	}
}

func WithArgs(args []string) Option {
	return func(c *Command) {
		c.args = args
	}
}

type Command struct {
	cmd        string
	args       []string
	inheritEnv bool
	environ    map[string]string
	interval   time.Duration

	msgCh chan kawa.MsgAck[types.Event]
}

func NewCommand(opts ...Option) *Command {
	ret := &Command{
		interval: 5 * time.Second,
		msgCh:    make(chan kawa.MsgAck[types.Event]),
	}
	for _, opt := range opts {
		opt(ret)
	}
	return ret
}

func (s *Command) Run(ctx context.Context) error {
	slog.Info(fmt.Sprintf("Command every %v: %s", s.interval, s.cmd))
	return s.recvLoop(ctx)
}

func (s *Command) recvLoop(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		newCtx, cancel := context.WithTimeout(ctx, s.interval)
		defer cancel()

		cmd := exec.CommandContext(newCtx, s.cmd, s.args...)
		cmd.Env = make([]string, 0)
		if s.inheritEnv {
			cmd.Env = append(cmd.Env, os.Environ()...)
		}
		for k, v := range s.environ {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			slog.Error(fmt.Sprintf("Error getting stdout pipe: %s", err))
			return err
		}
		_, err = cmd.StderrPipe()
		if err != nil {
			slog.Error(fmt.Sprintf("Error getting stderr pipe: %s", err))
			return err
		}

		err = cmd.Start()
		if err != nil {
			slog.Error(fmt.Sprintf("Error starting command: %s", err))
			return err
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Bytes()
			rawLog := make([]byte, len(line))
			copy(rawLog, line)

			msgAck := kawa.MsgAck[types.Event]{
				Msg: kawa.Message[types.Event]{
					Value: types.Event{
						EventTime:  time.Now(),
						SourceType: "command",
						RawLog:     rawLog,
					},
				},
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case s.msgCh <- msgAck:
			}
		}

		if err := scanner.Err(); err != nil {
			slog.Info(fmt.Sprintf("scanning err: %+v", err))
			return err
		}
		err = cmd.Wait()
		if err != nil {
			slog.Error(fmt.Sprintf("Error waiting for command: %s", err))
			return err
		}

		cancel()
	}
}

func (s *Command) Recv(ctx context.Context) (kawa.Message[types.Event], func(), error) {
	select {
	case <-ctx.Done():
		return kawa.Message[types.Event]{}, nil, ctx.Err()
	case msgAck := <-s.msgCh:
		return msgAck.Msg, msgAck.Ack, nil
	}
}
