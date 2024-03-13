package main

import "C"

import (
	"bytes"
	"flag"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io/ioutil"
	"log/slog"
	"os"
	"syscall"
	"strings"

	"github.com/nfnt/resize"
	//	"unsafe"
)

const MAX_WIDTH = 128
const MAX_HEIGHT = 128

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

func resize_img(file string) (image.Image, error) {
	img, err := load_img(file)
	if err != nil {
		return nil, err
	}

	m := resize.Thumbnail(MAX_WIDTH, MAX_HEIGHT, img, resize.Lanczos3)
	return m, nil
}

func img_equal(a image.Image, b string) (bool, error) {
	split := strings.Split(b, "/")
	name := split[len(split)-1]
	tmp_path := strings.Join([]string{"/tmp", name}, "/")

	err := save_img(a, tmp_path)
	if err != nil {
		return false, err
	}

	abytes, err := ioutil.ReadFile(tmp_path)
	if err != nil {
		return false, err
	}
	bbytes, err := ioutil.ReadFile(b)
	if err != nil {
		return false, err
	}

	return bytes.Equal(abytes, bbytes), nil
}

func save_img(img image.Image, path string) error {
	out, err := os.Create(path)
	if err != nil {
		slog.Error("failed to create file", "err", err, "path", path)
		return nil
	}
	defer out.Close()

	split := strings.Split(path, ".")
	ext := split[len(split)-1]
	if ext == "jpg" || ext == "jpeg" || ext == "JPG" || ext == "JPEG" {
		err := jpeg.Encode(out, img, nil)
		if err != nil {
			slog.Error("failed to encode jpg", "err", err)
			return nil
		}
	} else if ext == "png" || ext == "PNG" {
		err := png.Encode(out, img)
		if err != nil {
			slog.Error("failed to encode png", "err", err)
			return nil
		}
	} else if ext == "gif" || ext == "GIF" {
		err := gif.Encode(out, img, nil)
		if err != nil {
			slog.Error("failed to encode gif", "err", err)
			return nil
		}
	} else {
		slog.Error("unkown extension", "ext", ext)
		return nil
	}

	return nil
}

func main() {
	var check string
	var verbose bool

	flag.StringVar(&check, "check", "", "filepath of the thumbnail to check against")
	flag.BoolVar(&verbose, "verbose", false, "verbose logging")

	flag.Parse()
	if verbose {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
		slog.SetDefault(logger)
	} else {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
		slog.SetDefault(logger)
	}

	if len(flag.Args()) != 1 {
		slog.Error("Failed get image pathname")
		return
	}

	image_path := flag.Args()[0]

	// wait for snapshot
	syscall.Kill(syscall.Getpid(), syscall.SIGSTOP)

	thumbnail, err := resize_img(image_path)
	if err != nil {
		slog.Error("failed to resize image", "err", err, "filename", image_path)
		return
	}

	if len(check) != 0 {
		slog.Debug("comparing thumbnail", "filename", check)

		eq, err := img_equal(thumbnail, check)
		if err != nil {
			slog.Error("failed to check image equality", "err", err, "filename", check)
			return
		}
		if eq {
			slog.Info("OK: thumbnails are the same")
		} else {
			slog.Warn("ERR: thumbnails are not the same")
		}
	} else {
		split := strings.Split(image_path, "/")
		name := split[len(split)-1]
		path_components := append(split[:len(split)-2], []string{"thumbnails", name}...)
		thumbnail_path := strings.Join(path_components, "/")
		slog.Info("saving thumbnail", "thumbnail_path", thumbnail_path)

		err := save_img(thumbnail, thumbnail_path)
		if err != nil {
			slog.Info("failed to save image", "err", err)
		}
	}
}
