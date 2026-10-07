package churro

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"sync"
	"testing"
)

func TestGeneratorConcurrentReuseProducesDistinctLoaders(t *testing.T) {
	const count = 12
	generator := NewGenerator()
	defer generator.Close()
	source := []byte("WScript.Echo \"concurrent generation\"")
	wantSource := bytes.Clone(source)
	request := Request{Payload: VBScript{Source: source}}
	results := make([]Result, count)
	errorsByCall := make([]error, count)
	var workers sync.WaitGroup
	for i := range results {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			results[index], errorsByCall[index] = generator.Generate(context.Background(), request)
		}(i)
	}
	workers.Wait()
	seen := make(map[[sha256.Size]byte]int, count)
	for i, result := range results {
		if errorsByCall[i] != nil {
			t.Fatalf("Generate call %d: %v", i, errorsByCall[i])
		}
		if len(result.Loader) == 0 || result.StagedModule != nil {
			t.Fatalf("Generate call %d returned invalid embedded result", i)
		}
		digest := sha256.Sum256(result.Loader)
		if previous, exists := seen[digest]; exists {
			t.Fatalf("Generate calls %d and %d returned identical loaders", previous, i)
		}
		seen[digest] = i
	}
	if !bytes.Equal(source, wantSource) {
		t.Fatal("Generate mutated caller-owned payload source")
	}
}

func TestGeneratorConcurrentStagingPreservesRequestAndOwnsResults(t *testing.T) {
	const count = 8
	base, err := url.Parse("http://user:password@127.0.0.1:8080/modules/")
	if err != nil {
		t.Fatal(err)
	}
	generator := NewGenerator()
	defer generator.Close()
	source := []byte("var answer = 42;")
	wantSource := bytes.Clone(source)
	staging := &HTTPStaging{BaseURL: *base, ModuleName: "MODULE01"}
	request := Request{Payload: JScript{Source: source}, Staging: staging}
	results := make([]Result, count)
	errorsByCall := make([]error, count)
	var workers sync.WaitGroup
	for i := range results {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			results[index], errorsByCall[index] = generator.Generate(context.Background(), request)
		}(i)
	}
	workers.Wait()
	seenLoaders := make(map[[sha256.Size]byte]int, count)
	seenModules := make(map[[sha256.Size]byte]int, count)
	for i, result := range results {
		if errorsByCall[i] != nil {
			t.Fatalf("Generate call %d: %v", i, errorsByCall[i])
		}
		if len(result.Loader) == 0 || result.StagedModule == nil || len(result.StagedModule.Data) == 0 {
			t.Fatalf("Generate call %d returned incomplete staged result", i)
		}
		if result.StagedModule.Name != "MODULE01" || result.StagedModule.URL.String() != base.String()+"MODULE01" {
			t.Fatalf("Generate call %d returned unexpected module metadata: %+v", i, result.StagedModule)
		}
		loaderHash := sha256.Sum256(result.Loader)
		if previous, exists := seenLoaders[loaderHash]; exists {
			t.Fatalf("Generate calls %d and %d returned identical loaders", previous, i)
		}
		seenLoaders[loaderHash] = i
		moduleHash := sha256.Sum256(result.StagedModule.Data)
		if previous, exists := seenModules[moduleHash]; exists {
			t.Fatalf("Generate calls %d and %d returned identical encrypted modules", previous, i)
		}
		seenModules[moduleHash] = i
	}
	if staging.BaseURL.String() != base.String() || staging.ModuleName != "MODULE01" || !bytes.Equal(source, wantSource) {
		t.Fatal("Generate mutated caller-owned staging request")
	}
	untouchedLoader := bytes.Clone(results[1].Loader)
	untouchedModule := bytes.Clone(results[1].StagedModule.Data)
	results[0].Loader[0] ^= 0xff
	results[0].StagedModule.Data[0] ^= 0xff
	if !bytes.Equal(results[1].Loader, untouchedLoader) || !bytes.Equal(results[1].StagedModule.Data, untouchedModule) {
		t.Fatal("Generate returned aliased result byte slices")
	}
}

func TestGeneratePublicValidationFields(t *testing.T) {
	goodScript := JScript{Source: []byte("var x = 1;")}
	cases := []struct {
		name    string
		request Request
		field   string
	}{
		{"typed nil payload", Request{Payload: (*NativeDLL)(nil)}, "payload"},
		{"empty payload", Request{Payload: JScript{}}, "payload"},
		{"invalid format", Request{Payload: goodScript, Format: Format(255)}, "format"},
		{"invalid exit", Request{Payload: goodScript, Loader: LoaderConfig{Exit: ExitBehavior(255)}}, "loader.exit"},
		{"invalid entropy", Request{Payload: goodScript, Loader: LoaderConfig{Entropy: Entropy(255)}}, "loader.entropy"},
		{"zero host RVA", Request{Payload: goodScript, Loader: LoaderConfig{HostContinuation: &HostImageContinuation{}}}, "loader.hostContinuation.entryPointRVA"},
		{"invalid PE headers", Request{Payload: NativeDLL{Image: []byte{1}, PE: NativePEConfig{Headers: PEHeaders(255)}}}, "payload.pe.headers"},
		{"invalid decoy path", Request{Payload: NativeDLL{Image: []byte{1}, PE: NativePEConfig{DecoyModulePath: "bad\x00path"}}}, "payload.pe.decoyModulePath"},
		{"empty DLL export", Request{Payload: NativeDLL{Image: []byte{1}, Export: &NativeDLLExport{}}}, "payload.export.name"},
		{"missing managed class", Request{Payload: DotNetDLL{Assembly: []byte{1}, EntryPoint: DotNetStaticMethod{MethodName: "Run"}}}, "payload.entryPoint.typeName"},
		{"missing managed method", Request{Payload: DotNetDLL{Assembly: []byte{1}, EntryPoint: DotNetStaticMethod{TypeName: "Fixture"}}}, "payload.entryPoint.methodName"},
		{"invalid staging scheme", Request{Payload: goodScript, Staging: &HTTPStaging{BaseURL: url.URL{Scheme: "ftp", Host: "example.test"}}}, "staging.baseURL"},
		{"unsafe staging name", Request{Payload: goodScript, Staging: &HTTPStaging{BaseURL: url.URL{Scheme: "https", Host: "example.test"}, ModuleName: "../bad"}}, "staging.moduleName"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := Generate(context.Background(), test.request)
			var validation *ValidationError
			if !errors.As(err, &validation) || validation.Field != test.field {
				t.Fatalf("Generate error = %v, want ValidationError for %s", err, test.field)
			}
		})
	}
}
