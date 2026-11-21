// Command appicon 只用标准库就把 resources/icon.png 变成各平台发布要用的图标：
// Windows 的资源对象（.syso）和 Linux 的 hicolor 图标目录。
//
// 为什么需要它：`go tool mygo build` 会自己把图标写进 EXE、装进 .deb，但
// `go build`（scripts/package-*.sh 与两份 QUICKSTART 里的手动构建）不会——
// 打出来的 easyconnect-hub.exe 顶着 Go 的默认图标，Linux 包也没有桌面图标。
//
// 两种用法：
//
//	go run ./cmd/appicon -arch amd64 -out appicon_windows_amd64.syso
//	go run ./cmd/appicon -png-dir share/icons/hicolor -png-name easyconnect-hub
//
// Windows 资源对象的文件名形如 *_windows_<arch>.syso，只会被 GOOS=windows
// 且架构匹配的构建收进链接，其它平台的 `go vet ./...`、`go test ./...` 不受
// 影响；名字不以 mygo_ 开头，因此不与 mygo 自己写的资源冲突，用完应删掉。
//
// 图标缩放和 COFF 资源段的写法改编自 mygo 的 cmd/mygo/icon.go 与
// cmd/mygo/winres.go（MIT License，Copyright (c) 2026 MyGo contributors）。
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"slices"
)

// iconSizes 是写出的图标尺寸：Windows 图标组与 Linux hicolor 目录共用。
var iconSizes = []int{16, 24, 32, 48, 64, 128, 256}

func main() {
	iconPath := flag.String("icon", "resources/icon.png", "方形 PNG 图标")
	arch := flag.String("arch", "amd64", "Windows 目标架构：amd64、386、arm64")
	out := flag.String("out", "", "Windows 资源对象输出文件（默认 appicon_windows_<arch>.syso）")
	pngDir := flag.String("png-dir", "", "Linux 图标主题根目录，写出 <N>x<N>/apps/<name>.png")
	pngName := flag.String("png-name", "easyconnect-hub", "-png-dir 下的图标名")
	flag.Parse()

	src, err := os.ReadFile(*iconPath)
	if err != nil {
		fail(err)
	}
	images, err := iconImages(src)
	if err != nil {
		fail(fmt.Errorf("%s：%w", *iconPath, err))
	}
	if *pngDir != "" {
		writePNGIcons(*pngDir, *pngName, images)
		return
	}
	if *out == "" {
		*out = "appicon_windows_" + *arch + ".syso"
	}
	syso, err := winresSyso(images, *arch)
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, syso, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("Windows 资源：%s（%d 字节，%d 个尺寸）\n", *out, len(syso), len(images))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "appicon:", err)
	os.Exit(1)
}

// writePNGIcons 按 hicolor 的目录规则写出图标：桌面环境按目录名挑尺寸。
func writePNGIcons(root, name string, images [][]byte) {
	for i, size := range iconSizes {
		dir := filepath.Join(root, fmt.Sprintf("%dx%d", size, size), "apps")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fail(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".png"), images[i], 0o644); err != nil {
			fail(err)
		}
	}
	fmt.Printf("Linux 图标：%s（<N>x<N>/apps/%s.png，%d 个尺寸）\n", root, name, len(images))
}

// iconImages 把 src 渲染成 iconSizes 里每个尺寸的 PNG。
func iconImages(src []byte) ([][]byte, error) {
	img, err := png.Decode(bytes.NewReader(src))
	if err != nil {
		return nil, fmt.Errorf("图标必须是 PNG：%w", err)
	}
	b := img.Bounds()
	if b.Dx() != b.Dy() {
		return nil, fmt.Errorf("图标必须是正方形，实际 %dx%d", b.Dx(), b.Dy())
	}
	images := make([][]byte, len(iconSizes))
	for i, s := range iconSizes {
		var p bytes.Buffer
		if err := png.Encode(&p, resize(img, s)); err != nil {
			return nil, err
		}
		images[i] = p.Bytes()
	}
	return images, nil
}

// resize 把 img 缩放到 size x size：缩小时按面积平均，放大时双线性采样。
func resize(img image.Image, size int) *image.NRGBA {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))
	if w == 0 || h == 0 {
		return dst
	}
	sx, sy := float64(w)/float64(size), float64(h)/float64(size)
	at := func(x, y int) (float64, float64, float64, float64) {
		c := color.NRGBAModel.Convert(img.At(b.Min.X+min(max(x, 0), w-1), b.Min.Y+min(max(y, 0), h-1))).(color.NRGBA)
		a := float64(c.A)
		// 预乘，避免透明像素压暗边缘。
		return float64(c.R) * a, float64(c.G) * a, float64(c.B) * a, a
	}
	for y := range size {
		for x := range size {
			var r, g, bl, a, n float64
			if sx >= 1 {
				x0, x1 := int(float64(x)*sx), max(int(float64(x+1)*sx), int(float64(x)*sx)+1)
				y0, y1 := int(float64(y)*sy), max(int(float64(y+1)*sy), int(float64(y)*sy)+1)
				for yy := y0; yy < y1; yy++ {
					for xx := x0; xx < x1; xx++ {
						cr, cg, cb, ca := at(xx, yy)
						r, g, bl, a, n = r+cr, g+cg, bl+cb, a+ca, n+1
					}
				}
			} else {
				fx, fy := (float64(x)+0.5)*sx-0.5, (float64(y)+0.5)*sy-0.5
				x0, y0 := int(fx), int(fy)
				dx, dy := fx-float64(x0), fy-float64(y0)
				for _, s := range [4]struct {
					x, y int
					wt   float64
				}{{x0, y0, (1 - dx) * (1 - dy)}, {x0 + 1, y0, dx * (1 - dy)}, {x0, y0 + 1, (1 - dx) * dy}, {x0 + 1, y0 + 1, dx * dy}} {
					cr, cg, cb, ca := at(s.x, s.y)
					r, g, bl, a, n = r+cr*s.wt, g+cg*s.wt, bl+cb*s.wt, a+ca*s.wt, n+s.wt
				}
			}
			if a == 0 {
				continue
			}
			dst.SetNRGBA(x, y, color.NRGBA{R: uint8(r/a + 0.5), G: uint8(g/a + 0.5), B: uint8(bl/a + 0.5), A: uint8(a/n + 0.5)})
		}
	}
	return dst
}

// winresSyso 生成带 .rsrc 段的 COFF 对象：图标图像（RT_ICON）与指向它们的
// 图标组（RT_GROUP_ICON）。Go 链接器会把 .rsrc 段原样放进 EXE。
func winresSyso(images [][]byte, goarch string) ([]byte, error) {
	// COFF 的机器类型与相对地址的重定位类型。
	arch, ok := map[string]struct{ machine, relocation uint16 }{
		"amd64": {0x8664, 0x0003}, // IMAGE_REL_AMD64_ADDR32NB
		"arm64": {0xAA64, 0x0002}, // IMAGE_REL_ARM64_ADDR32NB
		"386":   {0x014C, 0x0007}, // IMAGE_REL_I386_DIR32NB
	}[goarch]
	if !ok {
		return nil, fmt.Errorf("不支持的架构 %s：只支持 amd64、386、arm64", goarch)
	}
	machine, relocation := arch.machine, arch.relocation

	const (
		rtIcon      = 3
		rtGroupIcon = 14
		langID      = 0x0409 // en-US
	)
	res := map[uint16]map[uint16][]byte{rtIcon: {}}
	var group bytes.Buffer
	_ = binary.Write(&group, binary.LittleEndian, [3]uint16{0, 1, uint16(len(images))})
	for i, img := range images {
		id := uint16(i + 1)
		res[rtIcon][id] = img
		dim := byte(iconSizes[i])
		if iconSizes[i] >= 256 {
			dim = 0
		}
		group.Write([]byte{dim, dim, 0, 0})
		_ = binary.Write(&group, binary.LittleEndian, [2]uint16{1, 32})
		_ = binary.Write(&group, binary.LittleEndian, uint32(len(img)))
		_ = binary.Write(&group, binary.LittleEndian, id)
	}
	res[rtGroupIcon] = map[uint16][]byte{1: group.Bytes()}

	// 资源段是三级目录（类型、ID、语言），然后是数据项，最后是数据。
	// 目录项用段内偏移指向子目录；数据项存相对虚拟地址，由链接器按
	// 重定位算出。
	types := sortedKeys(res)
	dirSize := func(n int) int { return 16 + 8*n }
	size := dirSize(len(types))
	for _, t := range types {
		size += dirSize(len(res[t])) + len(res[t])*dirSize(1)
	}
	entriesAt := size
	count := 0
	for _, t := range types {
		count += len(res[t])
	}
	dataAt := entriesAt + 16*count

	raw := make([]byte, dataAt)
	le := binary.LittleEndian
	dir := func(at, n int) {
		le.PutUint16(raw[at+14:], uint16(n)) // NumberOfIdEntries
	}
	var relocs []uint32
	var data bytes.Buffer
	dir(0, len(types))
	next := dirSize(len(types))
	entry := entriesAt
	for i, t := range types {
		le.PutUint32(raw[16+8*i:], uint32(t))
		le.PutUint32(raw[16+8*i+4:], uint32(next)|0x80000000)
		ids := sortedKeys(res[t])
		idDir := next
		dir(idDir, len(ids))
		next += dirSize(len(ids))
		for j, id := range ids {
			le.PutUint32(raw[idDir+16+8*j:], uint32(id))
			le.PutUint32(raw[idDir+16+8*j+4:], uint32(next)|0x80000000)
			dir(next, 1)
			le.PutUint32(raw[next+16:], langID)
			le.PutUint32(raw[next+20:], uint32(entry))
			next += dirSize(1)

			for data.Len()%8 != 0 {
				data.WriteByte(0)
			}
			le.PutUint32(raw[entry:], uint32(dataAt+data.Len())) // OffsetToData
			le.PutUint32(raw[entry+4:], uint32(len(res[t][id])))
			relocs = append(relocs, uint32(entry))
			entry += 16
			data.Write(res[t][id])
		}
	}
	raw = append(raw, data.Bytes()...)
	for len(raw)%4 != 0 {
		raw = append(raw, 0)
	}

	var out bytes.Buffer
	const headerSize, sectionHeaderSize = 20, 40
	rawAt := headerSize + sectionHeaderSize
	relocAt := rawAt + len(raw)
	symbolsAt := relocAt + 10*len(relocs)
	_ = binary.Write(&out, le, struct {
		Machine, Sections                   uint16
		Time, Symbols, SymbolCount          uint32
		OptionalHeaderSize, Characteristics uint16
	}{machine, 1, 0, uint32(symbolsAt), 1, 0, 0})
	_ = binary.Write(&out, le, struct {
		Name                                        [8]byte
		VirtualSize, VirtualAddress, RawSize, RawAt uint32
		RelocAt, LineNumbersAt                      uint32
		Relocs, LineNumbers                         uint16
		Characteristics                             uint32
	}{[8]byte{'.', 'r', 's', 'r', 'c'}, 0, 0, uint32(len(raw)), uint32(rawAt), uint32(relocAt), 0, uint16(len(relocs)), 0, 0x40000040})
	out.Write(raw)
	for _, r := range relocs {
		_ = binary.Write(&out, le, r)         // VirtualAddress
		_ = binary.Write(&out, le, uint32(0)) // 符号 0：本段
		_ = binary.Write(&out, le, relocation)
	}
	// 段符号，然后一个空的字符串表。
	out.Write([]byte{'.', 'r', 's', 'r', 'c', 0, 0, 0})
	_ = binary.Write(&out, le, uint32(0)) // Value
	_ = binary.Write(&out, le, uint16(1)) // SectionNumber
	_ = binary.Write(&out, le, uint16(0)) // Type
	out.Write([]byte{3, 0})               // IMAGE_SYM_CLASS_STATIC，无辅助符号
	_ = binary.Write(&out, le, uint32(4))
	return out.Bytes(), nil
}

func sortedKeys[V any](m map[uint16]V) []uint16 {
	keys := make([]uint16, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
