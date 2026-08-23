package pikpak

import (
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
)

func TestApplyBackupOptions(t *testing.T) {
	opt := &Options{
		BackupMode:        true,
		UseTrash:          true,
		UploadCutoff:      defaultUploadCutoff,
		UploadConcurrency: 4,
	}

	applyBackupOptions(opt)

	if opt.UseTrash {
		t.Fatal("backup mode must permanently remove replaced objects")
	}
	if opt.UploadCutoff != 0 {
		t.Fatalf("backup upload cutoff = %v, want 0", opt.UploadCutoff)
	}
	if opt.UploadConcurrency != 1 {
		t.Fatalf("backup upload concurrency = %d, want 1", opt.UploadConcurrency)
	}
}

func TestApplyBackupOptionsLeavesNormalModeUnchanged(t *testing.T) {
	opt := &Options{
		UseTrash:          true,
		UploadCutoff:      defaultUploadCutoff,
		UploadConcurrency: 4,
	}

	applyBackupOptions(opt)

	if !opt.UseTrash || opt.UploadCutoff != defaultUploadCutoff || opt.UploadConcurrency != 4 {
		t.Fatalf("normal PikPak options changed: %+v", opt)
	}
}

func TestBackupModeUsesStableComparisonMetadata(t *testing.T) {
	f := &Fs{opt: Options{BackupMode: true}}
	if got := f.Precision(); got != time.Nanosecond {
		t.Fatalf("backup precision = %v, want %v", got, time.Nanosecond)
	}

	o := &Object{fs: f, modTime: time.Now()}
	if got := o.ModTime(nil); !got.Equal(time.Unix(0, 0)) {
		t.Fatalf("backup object modtime = %v, want Unix epoch", got)
	}
	if err := o.SetModTime(nil, time.Now()); err != nil {
		t.Fatalf("backup SetModTime() returned %v", err)
	}
}

func TestNormalModeKeepsPikPakModTimeBehavior(t *testing.T) {
	f := &Fs{opt: Options{}}
	if got := f.Precision(); got != fs.ModTimeNotSupported {
		t.Fatalf("normal precision = %v, want %v", got, fs.ModTimeNotSupported)
	}

	o := &Object{fs: f}
	if err := o.SetModTime(nil, time.Now()); err == nil {
		t.Fatal("normal SetModTime() unexpectedly succeeded")
	}
}
