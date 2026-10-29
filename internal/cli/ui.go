package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/kaygaaf/tattlr/internal/approval"
	"github.com/kaygaaf/tattlr/internal/config"
	"github.com/kaygaaf/tattlr/internal/policy"
	"github.com/kaygaaf/tattlr/internal/ui"
)

func runUI(args []string, env Env) int {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	port := fs.Int("port", ui.DefaultPort, "port on 127.0.0.1 to listen on")
	home := fs.String("home", env.Home, "home folder whose audit log and policy to show")
	open := fs.Bool("open", false, "open the page in your browser")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, `Usage: tattlr ui [flags]

Runs a small web page on 127.0.0.1 with a live timeline of what the hooks
decided, the rap sheet, and an inbox for asks that Codex and Cursor file
edits can't show you. Those hooks wait for a click (approval_timeout in the
policy, 30s by default) and fall back to the policy if nobody answers.
Stop it with Ctrl+C.

Flags:`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *port < 0 || *port > 65535 {
		fmt.Fprintln(env.Stderr, "tattlr ui: --port must be 0 to 65535")
		return 2
	}

	// One UI per home: a second one would steal ui.json from the first.
	if in, err := approval.ReadInfo(*home); err == nil && listening(in.Port) {
		fmt.Fprintf(env.Stderr, "tattlr ui is already running: http://127.0.0.1:%d/?token=%s\n", in.Port, in.Login)
		return 1
	}

	ctx := env.Ctx
	if ctx == nil {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
	}
	s := ui.New(ui.Options{Home: *home, Port: *port})
	ln, err := s.Listen()
	if err != nil {
		fmt.Fprintf(env.Stderr, "tattlr ui: %v\nIs something else on port %d? Try --port.\n", err, *port)
		return 1
	}
	out := env.Stdout
	fmt.Fprintf(out, "tattlr ui is up. Open this link (the token is new every run):\n\n  %s\n\n", s.URL())
	pol, perr := policy.Load(config.PolicyPath(*home))
	switch {
	case perr != nil:
		fmt.Fprintf(out, "Policy problem: %v\n", perr)
	case pol.ApprovalTimeout > 0:
		fmt.Fprintf(out, "Asks from Codex and Cursor file edits wait %s here before the policy decides.\n", pol.ApprovalTimeout)
	default:
		fmt.Fprintln(out, "approval_timeout is 0, so the inbox is off. The timeline still works.")
	}
	fmt.Fprintln(out, "Only 127.0.0.1 can reach it. Ctrl+C to stop.")
	if *open {
		openBrowser(s.URL())
	}
	if err := s.Serve(ctx, ln); err != nil {
		fmt.Fprintln(env.Stderr, "tattlr ui:", err)
		return 1
	}
	fmt.Fprintln(out, "\ntattlr ui stopped. Hooks are back to the policy alone.")
	return 0
}

func listening(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 300*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if cmd.Start() == nil {
		_ = cmd.Process.Release()
	}
}
