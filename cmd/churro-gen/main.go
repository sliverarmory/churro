package main

import (
	"bytes"
	"context"
	"debug/pe"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/sliverarmory/churro"
)

var version = "dev"

type payloadOptions struct {
	class          string
	method         string
	runtimeVersion string
	appDomain      string
	headers        churro.PEHeaders
	decoy          string
	thread         bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("churro-gen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "input Windows x64 EXE, DLL, VBS, or JS path")
	output := flags.String("output", "loader.bin", "output path")
	class := flags.String("class", "", "managed DLL class name")
	method := flags.String("method", "", "native DLL export or managed DLL method")
	runtimeVersion := flags.String("runtime", "", "CLR runtime version override")
	domain := flags.String("domain", "", "CLR AppDomain name")
	formatName := flags.String("format", "bin", "output format: bin, base64, c, ruby, python, powershell, csharp, hex, uuid")
	exitName := flags.String("exit", "thread", "loader exit behavior: thread, process, block")
	entropyName := flags.String("entropy", "default", "output randomization: default, names, none")
	headersName := flags.String("headers", "overwrite", "native PE headers: overwrite, preserve")
	decoy := flags.String("decoy", "", "native PE decoy module path")
	thread := flags.Bool("thread", false, "run a native executable entry point in a new thread")
	server := flags.String("server", "", "HTTP or HTTPS base URL for a staged payload")
	moduleName := flags.String("modname", "", "staged module filename (default: generated)")
	moduleOutput := flags.String("module-output", "", "staged module output path (default: beside loader)")
	showVersion := flags.Bool("version", false, "print version information")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "churro-gen %s\n", version)
		return 0
	}
	if *input == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: churro-gen -input payload.dll [-method StartW] [-output loader.bin]")
		return 2
	}
	format, err := parseFormat(*formatName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	exit, err := parseExit(*exitName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	entropy, err := parseEntropy(*entropyName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	headers, err := parseHeaders(*headersName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	staging, err := stagingForFlags(*server, *moduleName, *moduleOutput)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(stderr, "read input: %v\n", err)
		return 1
	}
	payload, err := payloadForPath(*input, data, payloadOptions{
		class:          *class,
		method:         *method,
		runtimeVersion: *runtimeVersion,
		appDomain:      *domain,
		headers:        headers,
		decoy:          *decoy,
		thread:         *thread,
	})
	if err != nil {
		fmt.Fprintf(stderr, "configure payload: %v\n", err)
		return 2
	}
	result, err := churro.Generate(context.Background(), churro.Request{
		Payload: payload,
		Format:  format,
		Loader:  churro.LoaderConfig{Exit: exit, Entropy: entropy},
		Staging: staging,
	})
	if err != nil {
		fmt.Fprintf(stderr, "generate loader: %v\n", err)
		return 1
	}
	var stagedPath string
	if staging != nil {
		if result.StagedModule == nil {
			fmt.Fprintln(stderr, "generation did not return the requested staged module")
			return 1
		}
		if filepath.Base(result.StagedModule.Name) != result.StagedModule.Name ||
			result.StagedModule.Name == "." || result.StagedModule.Name == ".." {
			fmt.Fprintln(stderr, "generation returned an unsafe staged module name")
			return 1
		}
		stagedPath = *moduleOutput
		if stagedPath == "" {
			stagedPath = filepath.Join(filepath.Dir(*output), result.StagedModule.Name)
		}
		loaderPath, loaderErr := filepath.Abs(*output)
		stagedAbs, stagedErr := filepath.Abs(stagedPath)
		if loaderErr != nil || stagedErr != nil || loaderPath == stagedAbs {
			fmt.Fprintln(stderr, "staged module output must differ from loader output")
			return 2
		}
	}
	if err := writeOutput(*output, result.Loader); err != nil {
		fmt.Fprintf(stderr, "write loader: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (%d bytes)\n", *output, len(result.Loader))
	if staging != nil {
		if err := writeOutput(stagedPath, result.StagedModule.Data); err != nil {
			fmt.Fprintf(stderr, "write staged module: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote staged module %s (%d bytes)\n", stagedPath, len(result.StagedModule.Data))
	}
	return 0
}

func stagingForFlags(server, moduleName, moduleOutput string) (*churro.HTTPStaging, error) {
	if server == "" {
		if moduleName != "" || moduleOutput != "" {
			return nil, errors.New("-modname and -module-output require -server")
		}
		return nil, nil
	}
	baseURL, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("parse -server URL: %w", err)
	}
	return &churro.HTTPStaging{BaseURL: *baseURL, ModuleName: moduleName}, nil
}

func writeOutput(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func parseFormat(value string) (churro.Format, error) {
	switch strings.ToLower(value) {
	case "bin", "binary":
		return churro.FormatBinary, nil
	case "base64", "b64":
		return churro.FormatBase64, nil
	case "c":
		return churro.FormatC, nil
	case "ruby":
		return churro.FormatRuby, nil
	case "python", "py":
		return churro.FormatPython, nil
	case "powershell", "ps1":
		return churro.FormatPowerShell, nil
	case "csharp", "cs":
		return churro.FormatCSharp, nil
	case "hex":
		return churro.FormatHex, nil
	case "uuid":
		return churro.FormatUUID, nil
	default:
		return 0, fmt.Errorf("unsupported output format %q", value)
	}
}

func parseExit(value string) (churro.ExitBehavior, error) {
	switch strings.ToLower(value) {
	case "thread":
		return churro.ExitThread, nil
	case "process":
		return churro.ExitProcess, nil
	case "block":
		return churro.ExitBlock, nil
	default:
		return 0, fmt.Errorf("unsupported exit behavior %q", value)
	}
}

func parseEntropy(value string) (churro.Entropy, error) {
	switch strings.ToLower(value) {
	case "default":
		return churro.EntropyDefault, nil
	case "names":
		return churro.EntropyNames, nil
	case "none":
		return churro.EntropyNone, nil
	default:
		return 0, fmt.Errorf("unsupported entropy mode %q", value)
	}
}

func parseHeaders(value string) (churro.PEHeaders, error) {
	switch strings.ToLower(value) {
	case "overwrite":
		return churro.PEHeadersOverwrite, nil
	case "preserve":
		return churro.PEHeadersPreserve, nil
	default:
		return 0, fmt.Errorf("unsupported PE header mode %q", value)
	}
}

func payloadForPath(path string, data []byte, options payloadOptions) (churro.Payload, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe":
		managed, dll, err := inspectPE(data)
		if err != nil {
			return nil, err
		}
		if dll {
			return nil, errors.New("input has an .exe name but PE contents identify a DLL")
		}
		if options.class != "" || options.method != "" {
			return nil, errors.New("DLL invocation flags are only valid with a DLL input")
		}
		if managed {
			if options.thread || options.decoy != "" || options.headers != churro.PEHeadersOverwrite {
				return nil, errors.New("native PE flags are not valid with a managed executable")
			}
			return churro.DotNetExecutable{
				Assembly: data,
				Runtime:  churro.DotNetRuntime{Version: options.runtimeVersion, AppDomain: options.appDomain},
			}, nil
		}
		if options.runtimeVersion != "" || options.appDomain != "" {
			return nil, errors.New("-runtime and -domain require a managed input")
		}
		flags := churro.NativeExecutableFlags(0)
		if options.thread {
			flags |= churro.NativeExecutableRunInThread
		}
		return churro.NativeExecutable{
			Image: data,
			Flags: flags,
			PE:    churro.NativePEConfig{Headers: options.headers, DecoyModulePath: options.decoy},
		}, nil
	case ".dll":
		managed, dll, err := inspectPE(data)
		if err != nil {
			return nil, err
		}
		if !dll {
			return nil, errors.New("input has a .dll name but PE contents identify an executable")
		}
		if options.thread {
			return nil, errors.New("-thread is only valid with a native executable")
		}
		if managed {
			if options.decoy != "" || options.headers != churro.PEHeadersOverwrite {
				return nil, errors.New("native PE flags are not valid with a managed DLL")
			}
			return churro.DotNetDLL{
				Assembly: data,
				EntryPoint: churro.DotNetStaticMethod{
					TypeName: options.class, MethodName: options.method,
				},
				Runtime: churro.DotNetRuntime{Version: options.runtimeVersion, AppDomain: options.appDomain},
			}, nil
		}
		if options.class != "" || options.runtimeVersion != "" || options.appDomain != "" {
			return nil, errors.New("-class, -runtime, and -domain require a managed DLL")
		}
		var export *churro.NativeDLLExport
		if options.method != "" {
			export = &churro.NativeDLLExport{Name: options.method}
		}
		return churro.NativeDLL{
			Image:  data,
			Export: export,
			PE:     churro.NativePEConfig{Headers: options.headers, DecoyModulePath: options.decoy},
		}, nil
	case ".vbs":
		if options.hasInvocationFlags() {
			return nil, errors.New("invocation flags are not valid with a VBScript input")
		}
		return churro.VBScript{Source: data}, nil
	case ".js":
		if options.hasInvocationFlags() {
			return nil, errors.New("invocation flags are not valid with a JScript input")
		}
		return churro.JScript{Source: data}, nil
	default:
		return nil, fmt.Errorf("unsupported input extension %q", filepath.Ext(path))
	}
}

func (options payloadOptions) hasInvocationFlags() bool {
	return options.class != "" || options.method != "" ||
		options.runtimeVersion != "" || options.appDomain != "" ||
		options.decoy != "" || options.thread || options.headers != churro.PEHeadersOverwrite
}

func inspectPE(data []byte) (managed bool, dll bool, err error) {
	file, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return false, false, fmt.Errorf("parse PE input: %w", err)
	}
	defer file.Close()
	dll = file.Characteristics&pe.IMAGE_FILE_DLL != 0
	const comDescriptor = pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		managed = header.NumberOfRvaAndSizes > comDescriptor && header.DataDirectory[comDescriptor].VirtualAddress != 0
	case *pe.OptionalHeader64:
		managed = header.NumberOfRvaAndSizes > comDescriptor && header.DataDirectory[comDescriptor].VirtualAddress != 0
	default:
		return false, false, fmt.Errorf("parse PE input: unsupported optional header type %T", file.OptionalHeader)
	}
	return managed, dll, nil
}
