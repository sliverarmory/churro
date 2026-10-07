// Package churro generates 64-bit Windows loaders in-process using an
// embedded Windows loader. The package accepts and returns bytes; it never
// reads or writes host files.
package churro

import "net/url"

// Request describes one loader generation operation.
type Request struct {
	Payload Payload
	Format  Format
	Loader  LoaderConfig
	Staging *HTTPStaging
}

// LoaderConfig controls behavior shared by all generated loaders.
type LoaderConfig struct {
	Exit             ExitBehavior
	Entropy          Entropy
	Compression      Compression
	HostContinuation *HostImageContinuation
}

// HostImageContinuation resumes the current thread at an RVA in the host image
// after starting payload processing on a new thread.
type HostImageContinuation struct {
	EntryPointRVA uint32
}

// HTTPStaging configures a loader that retrieves its payload over HTTP or
// HTTPS. The package returns the module bytes but does not upload them.
type HTTPStaging struct {
	BaseURL    url.URL
	ModuleName string
}

// Payload is implemented by the payload-specific request structures.
type Payload interface {
	churroPayload()
}

// NativePEConfig controls native PE mapping behavior.
type NativePEConfig struct {
	Headers         PEHeaders
	DecoyModulePath string
}

// PEHeaders controls whether the native mapper preserves the payload's PE
// headers.
type PEHeaders uint8

const (
	// PEHeadersOverwrite allows the loader to overwrite mapped PE headers and
	// is the zero-value default.
	PEHeadersOverwrite PEHeaders = iota
	// PEHeadersPreserve keeps the mapped payload's PE headers.
	PEHeadersPreserve
)

// NativeExecutable describes an unmanaged Windows executable image.
type NativeExecutable struct {
	Image     []byte
	Arguments string
	Flags     NativeExecutableFlags
	PE        NativePEConfig
}

func (NativeExecutable) churroPayload() {}

// NativeExecutableFlags controls unmanaged executable invocation behavior.
type NativeExecutableFlags uint32

const (
	// NativeExecutableRunInThread runs the executable entry point on a new
	// thread and intercepts common process-exit imports where possible.
	NativeExecutableRunInThread NativeExecutableFlags = 1 << iota
)

const nativeExecutableFlagsMask = NativeExecutableRunInThread

// NativeDLL describes an unmanaged Windows DLL image. DllMain is always
// invoked. Export optionally selects a named export to invoke afterward.
type NativeDLL struct {
	Image  []byte
	Export *NativeDLLExport
	PE     NativePEConfig
}

func (NativeDLL) churroPayload() {}

// NativeDLLExport identifies a native DLL export. When Arguments is empty,
// the export is called without a parameter. Otherwise the loader passes one
// pointer to the argument string, encoded as UTF-8 or UTF-16 as selected.
type NativeDLLExport struct {
	Name      string
	Arguments string
	Unicode   bool
}

// DotNetRuntime configures managed payload hosting. Empty fields use the
// assembly metadata and Churro defaults.
type DotNetRuntime struct {
	Version   string
	AppDomain string
}

const (
	// DotNetRuntimeV2 selects CLR v2.
	DotNetRuntimeV2 = "v2.0.50727"
	// DotNetRuntimeV4 selects CLR v4.
	DotNetRuntimeV4 = "v4.0.30319"
)

// DotNetExecutable describes a managed Windows executable assembly. Arguments
// is a raw command-line tail parsed into the entry point's string array.
type DotNetExecutable struct {
	Assembly  []byte
	Arguments string
	Runtime   DotNetRuntime
}

func (DotNetExecutable) churroPayload() {}

// DotNetDLL describes a managed Windows library assembly.
type DotNetDLL struct {
	Assembly   []byte
	EntryPoint DotNetStaticMethod
	Runtime    DotNetRuntime
}

func (DotNetDLL) churroPayload() {}

// DotNetStaticMethod identifies a public static method. Arguments is a raw
// command-line tail parsed into one string argument per method parameter.
type DotNetStaticMethod struct {
	TypeName   string
	MethodName string
	Arguments  string
}

// VBScript describes VBScript source encoded for the target Windows
// environment.
type VBScript struct {
	Source []byte
}

func (VBScript) churroPayload() {}

// JScript describes JScript source encoded for the target Windows environment.
type JScript struct {
	Source []byte
}

func (JScript) churroPayload() {}

// Result contains the generated loader and, for staged generation, its module.
// Returned byte slices are owned by the caller. Binary loader bytes must be
// executed from a page-aligned allocation.
type Result struct {
	Loader       []byte
	StagedModule *StagedModule
}

// StagedModule is the payload module to host at URL.
type StagedModule struct {
	Name string
	URL  url.URL
	Data []byte
}

// Format selects the representation of Result.Loader.
type Format uint8

const (
	// FormatBinary returns raw shellcode bytes and is the zero-value default.
	FormatBinary Format = iota
	// FormatBase64 returns Base64 text.
	FormatBase64
	// FormatC returns a C source representation.
	FormatC
	// FormatRuby returns a Ruby source representation.
	FormatRuby
	// FormatPython returns a Python 3 bytes-source representation.
	FormatPython
	// FormatPowerShell returns a PowerShell source representation.
	FormatPowerShell
	// FormatCSharp returns a C# source representation.
	FormatCSharp
	// FormatHex returns hexadecimal text.
	FormatHex
	// FormatUUID returns UUID strings.
	FormatUUID
)

// ExitBehavior controls what the loader does after the payload returns.
type ExitBehavior uint8

const (
	// ExitThread exits the current thread and is the zero-value default.
	ExitThread ExitBehavior = iota
	// ExitProcess exits the host process.
	ExitProcess
	// ExitBlock blocks instead of returning.
	ExitBlock
)

// Entropy controls optional per-output randomization.
type Entropy uint8

const (
	// EntropyDefault randomizes names and cryptographic material. It is the
	// zero-value default.
	EntropyDefault Entropy = iota
	// EntropyNames randomizes names without encrypting the module and instance.
	EntropyNames
	// EntropyNone disables optional name and cryptographic randomization.
	EntropyNone
)

// Compression selects the payload module encoding before optional encryption.
type Compression uint8

const (
	// CompressionNone leaves the payload bytes unchanged and is the default.
	CompressionNone Compression = iota
	// CompressionAPLib uses the loader's aPLib decoder.
	CompressionAPLib
)
