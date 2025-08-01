package main

import (
	"bufio"
	"flag"
	"image"
	"image/png"
	"image/jpeg"
	"log/slog"
	"os"
	"syscall"
	"strings"
	"time"
	"image/color"
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/nfnt/resize"
	//	"unsafe"
)

const MAX_WIDTH = 64
const MAX_HEIGHT = 64

func load_img(file string) (image.Image, error) {
	f, err := os.Open(file)

	if err != nil {
		return nil, err
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		return nil, err
	}
	return img, nil
}

func resize_img(img image.Image) (image.Image, error) {
	m := resize.Thumbnail(MAX_WIDTH, MAX_HEIGHT, img, resize.Lanczos3)
	return m, nil
}

func save_img(img image.Image, path string) error {
	out, err := os.Create(path)
	if err != nil {
		slog.Error("failed to create file" ,"err", err, "path", path)
		return err
	}
	defer out.Close()

	split := strings.Split(path, ".")
	ext := split[len(split) - 1]
	if ext == "jpg" || ext == "jpeg" || ext == "JPG" || ext == "JPEG" {
		err := jpeg.Encode(out, img, nil)
		if err != nil {
			slog.Error("failed to encode jpg", "err", err)
			return err
		}
	} else if ext == "png" || ext == "PNG" {
		err := png.Encode(out, img)
		if err != nil {
			slog.Error("failed to encode png", "err", err)
			return err
		}
	} else {
		slog.Error("unkown extension", "ext", ext)
		return err
	}

	return nil
}

func writeResp(file *os.File, resp string) {
	_, err := file.WriteString(resp)
	if err != nil {
		fmt.Println("Error writing response:", err)
	}
}

func NewVersion() {
	file, err := os.OpenFile("/serverless/chan0", os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	for {
		cmd, err := reader.ReadString('\n')
		if err != nil {
			if err.Error() != "EOF" {
				fmt.Println("Error reading line:", err)
			}
			break
		}

		cmd = strings.TrimSpace(cmd)

		if cmd == "SNAPSHOT_PREPARE" {
			for i := 1; i < 10; i++ {
				runtime.GC()
				debug.FreeOSMemory()
			}
			writeResp(file, "OK")
			continue
		}

		img, err := load_img(cmd)
		if err != nil {
			slog.Error("failed to load image", "err", err, "filename", cmd)
			return
		}

		thumbnail, err := resize_img(img)
		if err != nil {
			slog.Error("failed to resize image", "err", err)
			return
		}

		r, g, b, a := thumbnail.At(10, 10).RGBA()
		if r * g * b * a == 0xdeadbeef {
			slog.Error("what a surprise!");
		}


		// err = save_img(thumbnail, "/tmp/image.png")
		// if err != nil {
		// 	slog.Error("failed to save img", "err", err)
		// 	return
		// }

		writeResp(file, "OK")
	}
}

var newVersion = flag.Bool("new_version", false, "Flag to trigger new version")

func main() {
	flag.Parse()

	if *newVersion {
		NewVersion()
		return
	}

	if len(flag.Args()) < 1 {
		slog.Error("Failed get image pathname")
		return
	}

	image_path := flag.Args()[0]
	img, err := load_img(image_path)
	if err != nil {
		slog.Error("failed to load image", "err", err, "filename", image_path)
		return
	}

	prog_name := "go_resizer"
	if len(flag.Args()) > 1 {
		prog_name = flag.Args()[1]
	}

	var durations []time.Duration
	var colors []color.Color

	value, dontstop := os.LookupEnv("DONTSTOP")
	_ = value

	// warm up the function
	for i := 1; i < 10; i++ {
		start := time.Now()
		thumbnail, err := resize_img(img)
		elapsed := time.Since(start)
		if err != nil {
			slog.Error("failed to resize image", "err", err, "filename", image_path)
			return
		}
		durations = append(durations, elapsed)
		colors = append(colors, thumbnail.At(1,1))
	}

	pid := os.Getpid()

	for i := 1; i < 10; i++ {
		runtime.GC()
		debug.FreeOSMemory()
	}

	// stop the process for initializing profiling
	if !dontstop {
		syscall.Kill(pid, syscall.SIGSTOP)
	}

	start := time.Now()

	// run the function one more time
	thumbnail, err := resize_img(img)
	if err != nil {
		slog.Error("failed to resize image", "err", err, "filename", image_path)
		return
	}

	elapsed := time.Since(start)

	var result strings.Builder
	result.WriteString("DATA  {\"warmup\": [")

	for i, warmup := range durations {
		if i > 0 {
			result.WriteString(", ")
		}
		result.WriteString(fmt.Sprintf("%d", warmup.Microseconds()))
	}

	result.WriteString("], \"cold\": [")
	result.WriteString(fmt.Sprintf("%d", elapsed.Microseconds()))
	result.WriteString("], \"program\": \"")
	result.WriteString(prog_name)
	result.WriteString("\"}")

	fmt.Println(result.String())

	os.Stdout.Sync()

	syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)

	slog.Info("colors ", colors)
	slog.Info("colors ", thumbnail.At(1,1))
}