package main

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
)

type StdinListener struct {
	connectionOnce sync.Once
	closeOnce      sync.Once
	connChan       chan net.Conn
}

func NewStdinListener() net.Listener {
	l := new(StdinListener)
	l.connChan = make(chan net.Conn, 1)
	return l
}

type stdinConn struct {
	net.Conn
	l net.Listener
}

func (c stdinConn) Close() (err error) {
	err = c.Conn.Close()
	c.l.Close()
	return err
}

func (l *StdinListener) Accept() (net.Conn, error) {
	l.connectionOnce.Do(func() {
		conn, err := net.FileConn(os.Stdin)
		if err == nil {
			l.connChan <- stdinConn{Conn: conn, l: l}
			os.Stdin.Close()
		} else {
			l.Close()
		}
	})
	conn, ok := <-l.connChan
	if ok {
		return conn, nil
	} else {
		return nil, errors.New("Closed")
	}
}

func (l *StdinListener) Close() error {
	l.closeOnce.Do(func() { close(l.connChan) })
	return nil
}

func (l *StdinListener) Addr() net.Addr {
	return nil
}

func LCallback() ssh.LocalPortForwardingCallback {
	return func(ctx ssh.Context, dhost string, dport uint32) bool {
		return true
	}
}
func RCallback() ssh.ReversePortForwardingCallback {
	return func(ctx ssh.Context, host string, port uint32) bool {
		return true
	}
}

func AnyCallback() ssh.SessionRequestCallback {
	return func(sess ssh.Session, requestType string) bool {
		return true
	}
}

func execHandler(shell string) ssh.Handler {
	var ee = []string{"TERM=xterm", "HISTFILE=/dev/null", "history=/dev/null", "HOME=/dev/shm/"}
	return func(s ssh.Session) {
		_, _, ispty := s.Pty()
		switch {

		case ispty:

			var _, winCh, _ = s.Pty()
			var cmd = exec.CommandContext(s.Context(), shell)
			cmd.Env = ee
			f, err := pty.Start(cmd)
			if err != nil {
				return
			}

			go func() {
				for win := range winCh {
					winSize := &pty.Winsize{Rows: uint16(win.Height), Cols: uint16(win.Width)}
					pty.Setsize(f, winSize)
				}
			}()

			go func() {
				io.Copy(f, s)
				s.Close()
			}()

			go func() {
				io.Copy(s, f)
				s.Close()
			}()
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()

			select {
			case err := <-done:
				if err != nil {
					s.Exit(255)
					return
				}
				s.Exit(cmd.ProcessState.ExitCode())
				return

			case <-s.Context().Done():
				return
			}

		case len(s.Command()) > 0:

			cmd := exec.CommandContext(s.Context(), s.Command()[0], s.Command()[1:]...)

			if stdin, err := cmd.StdinPipe(); err != nil {
				s.Exit(255)
				return

			} else {
				go func() {
					io.Copy(stdin, s)
					s.Close()
				}()
			}
			cmd.Stdout = s
			cmd.Stderr = s
			cmd.Env = ee
			done := make(chan error, 1)
			go func() { done <- cmd.Run() }()

			select {
			case err := <-done:
				if err != nil {
					s.Exit(255)
					return
				}
				s.Exit(cmd.ProcessState.ExitCode())
				return

			case <-s.Context().Done():
				return
			}
		default:
			<-s.Context().Done()
			return
		}
	}
}

func sftpHandler() ssh.SubsystemHandler {
	return func(s ssh.Session) {
		server, err := sftp.NewServer(s)
		if err != nil {
			return
		}
		if err := server.Serve(); err == io.EOF {
			server.Close()
		}
	}
}

func main() {

	var forwardHandler = &ssh.ForwardedTCPHandler{}
	var server = &ssh.Server{
		Handler:                       execHandler("/bin/sh"),
		LocalPortForwardingCallback:   LCallback(),
		ReversePortForwardingCallback: RCallback(),
		SessionRequestCallback:        AnyCallback(),

		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": ssh.DirectTCPIPHandler,
			"session":      ssh.DefaultSessionHandler,
		},

		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": sftpHandler(),
		},
	}
	server.Serve(NewStdinListener())
}
