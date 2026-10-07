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
	"strconv"
	"strings"

	"github.com/sliverarmory/churro"
)

var version = "dev"

type payloadOptions struct {
	class          string
	method         string
	arguments      string
	unicode        bool
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
	output := flags.String("output", "", "output path (default: loader extension for format)")
	class := flags.String("class", "", "managed DLL class name")
	method := flags.String("method", "", "native DLL export or managed DLL method")
	runtimeVersion := flags.String("runtime", "", "CLR runtime version override")
	domain := flags.String("domain", "", "CLR AppDomain name")
	formatName := flags.String("format", "bin", "output format: bin, base64, c, ruby, python, powershell, csharp, hex, uuid")
	exitName := flags.String("exit", "thread", "loader exit behavior: thread, process, block")
	entropyName := flags.String("entropy", "default", "output randomization: default, names, none")
	compressionName := flags.String("compression", "none", "payload compression: none, aplib")
	chunked := flags.String("chunked", "1", "deprecated compatibility flag; dispatch is always enabled")
	headersName := flags.String("headers", "overwrite", "native PE headers: overwrite, preserve")
	decoy := flags.String("decoy", "", "native PE decoy module path")
	thread := flags.Bool("thread", false, "run a native executable entry point in a new thread")
	arguments := flags.String("args", "", "native target arguments or native DLL export argument")
	unicode := flags.Bool("unicode", false, "pass native DLL export argument as UTF-16")
	fork := flags.String("fork", "", "host image continuation entry point RVA (hex)")
	server := flags.String("server", "", "HTTP or HTTPS base URL for a staged payload")
	moduleName := flags.String("modname", "", "staged module filename (default: generated)")
	moduleOutput := flags.String("module-output", "", "staged module output path (default: beside loader)")
	bundleDir := flags.String("loader-bundle", "", "directory containing a custom native loader bundle")
	showVersion := flags.Bool("version", false, "print version information")
	flags.StringVar(input, "i", "", "alias for -input")
	flags.StringVar(input, "file", "", "alias for -input")
	flags.StringVar(output, "o", "", "alias for -output")
	flags.StringVar(class, "c", "", "alias for -class")
	flags.StringVar(method, "m", "", "alias for -method")
	flags.StringVar(method, "function", "", "alias for -method")
	flags.StringVar(runtimeVersion, "r", "", "alias for -runtime")
	flags.StringVar(domain, "d", "", "alias for -domain")
	flags.StringVar(formatName, "f", "bin", "alias for -format")
	flags.StringVar(exitName, "x", "thread", "alias for -exit")
	flags.StringVar(entropyName, "e", "default", "alias for -entropy")
	flags.StringVar(headersName, "k", "overwrite", "alias for -headers")
	flags.StringVar(decoy, "j", "", "alias for -decoy")
	flags.BoolVar(thread, "t", false, "alias for -thread")
	flags.StringVar(arguments, "p", "", "alias for -args")
	flags.StringVar(arguments, "params", "", "alias for -args")
	flags.BoolVar(unicode, "w", false, "alias for -unicode")
	flags.StringVar(fork, "y", "", "alias for -fork")
	flags.StringVar(fork, "oep", "", "alias for -fork")
	flags.StringVar(server, "s", "", "alias for -server")
	flags.StringVar(moduleName, "n", "", "alias for -modname")
	flags.StringVar(chunked, "g", "1", "alias for -chunked")
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
	if *chunked != "0" && *chunked != "1" {
		fmt.Fprintln(stderr, "-chunked is deprecated and accepts only 0 or 1")
		return 2
	}
	format, err := parseFormat(*formatName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	outputPath := *output
	if outputPath == "" {
		outputPath = defaultOutputForFormat(format)
	}
	continuation, err := parseContinuation(*fork)
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
	compression, err := parseCompression(*compressionName)
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
		arguments:      *arguments,
		unicode:        *unicode,
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
	ctx := context.Background()
	var generator *churro.Generator
	if *bundleDir == "" {
		generator = churro.NewGenerator()
	} else {
		bundle, readErr := readBundleDir(*bundleDir)
		if readErr != nil {
			fmt.Fprintf(stderr, "read loader bundle: %v\n", readErr)
			return 2
		}
		generator, err = churro.NewWithLoader(ctx, bundle)
		if err != nil {
			fmt.Fprintf(stderr, "configure loader bundle: %v\n", err)
			return 2
		}
	}
	defer generator.Close()
	result, err := generator.Generate(ctx, churro.Request{
		Payload: payload,
		Format:  format,
		Loader: churro.LoaderConfig{
			Exit: exit, Entropy: entropy, Compression: compression,
			HostContinuation: continuation,
		},
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
			stagedPath = filepath.Join(filepath.Dir(outputPath), result.StagedModule.Name)
		}
		loaderPath, loaderErr := filepath.Abs(outputPath)
		stagedAbs, stagedErr := filepath.Abs(stagedPath)
		if loaderErr != nil || stagedErr != nil || loaderPath == stagedAbs {
			fmt.Fprintln(stderr, "staged module output must differ from loader output")
			return 2
		}
	}
	if err := writeOutput(outputPath, result.Loader); err != nil {
		fmt.Fprintf(stderr, "write loader: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (%d bytes)\n", outputPath, len(result.Loader))
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
	case "1", "bin", "binary":
		return churro.FormatBinary, nil
	case "2", "base64", "b64":
		return churro.FormatBase64, nil
	case "3", "c":
		return churro.FormatC, nil
	case "4", "ruby", "rb":
		return churro.FormatRuby, nil
	case "5", "python", "py":
		return churro.FormatPython, nil
	case "6", "powershell", "ps1", "ps":
		return churro.FormatPowerShell, nil
	case "7", "csharp", "cs":
		return churro.FormatCSharp, nil
	case "8", "hex":
		return churro.FormatHex, nil
	case "9", "uuid":
		return churro.FormatUUID, nil
	default:
		return 0, fmt.Errorf("unsupported output format %q", value)
	}
}

func defaultOutputForFormat(format churro.Format) string {
	switch format {
	case churro.FormatBase64:
		return "loader.b64"
	case churro.FormatC:
		return "loader.c"
	case churro.FormatRuby:
		return "loader.rb"
	case churro.FormatPython:
		return "loader.py"
	case churro.FormatPowerShell:
		return "loader.ps1"
	case churro.FormatCSharp:
		return "loader.cs"
	case churro.FormatHex:
		return "loader.hex"
	case churro.FormatUUID:
		return "loader.uuid"
	default:
		return "loader.bin"
	}
}

func parseContinuation(raw string) (*churro.HostImageContinuation, error) {
	if raw == "" {
		return nil, nil
	}
	value := strings.TrimPrefix(strings.ToLower(raw), "0x")
	rva, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid -fork RVA %q: %w", raw, err)
	}
	if rva == 0 {
		return nil, nil
	}
	return &churro.HostImageContinuation{EntryPointRVA: uint32(rva)}, nil
}

func parseExit(value string) (churro.ExitBehavior, error) {
	switch strings.ToLower(value) {
	case "1", "thread":
		return churro.ExitThread, nil
	case "2", "process":
		return churro.ExitProcess, nil
	case "3", "block":
		return churro.ExitBlock, nil
	default:
		return 0, fmt.Errorf("unsupported exit behavior %q", value)
	}
}

func parseEntropy(value string) (churro.Entropy, error) {
	switch strings.ToLower(value) {
	case "3", "default", "full":
		return churro.EntropyDefault, nil
	case "2", "names", "low":
		return churro.EntropyNames, nil
	case "1", "none":
		return churro.EntropyNone, nil
	default:
		return 0, fmt.Errorf("unsupported entropy mode %q", value)
	}
}

func parseCompression(value string) (churro.Compression, error) {
	switch strings.ToLower(value) {
	case "none":
		return churro.CompressionNone, nil
	case "aplib":
		return churro.CompressionAPLib, nil
	default:
		return 0, fmt.Errorf("unsupported compression mode %q", value)
	}
}

func parseHeaders(value string) (churro.PEHeaders, error) {
	switch strings.ToLower(value) {
	case "1", "overwrite":
		return churro.PEHeadersOverwrite, nil
	case "2", "preserve":
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
		if options.unicode {
			return nil, errors.New("-unicode is only valid with a native DLL export")
		}
		if managed {
			if options.thread || options.arguments != "" || options.decoy != "" || options.headers != churro.PEHeadersOverwrite {
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
			Image:     data,
			Arguments: options.arguments,
			Flags:     flags,
			PE:        churro.NativePEConfig{Headers: options.headers, DecoyModulePath: options.decoy},
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
			if options.arguments != "" || options.unicode || options.decoy != "" || options.headers != churro.PEHeadersOverwrite {
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
		if options.method == "" && (options.arguments != "" || options.unicode) {
			return nil, errors.New("-args and -unicode require a native DLL -method")
		}
		var export *churro.NativeDLLExport
		if options.method != "" {
			export = &churro.NativeDLLExport{Name: options.method, Arguments: options.arguments, Unicode: options.unicode}
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
		options.arguments != "" || options.unicode || options.decoy != "" ||
		options.thread || options.headers != churro.PEHeadersOverwrite
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
