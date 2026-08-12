package substrate

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestImportBoundary enforces §12: the substrate imports the standard library
// and third-party modules only — never the host repository's packages. This
// is what keeps extraction a move instead of a redesign. Test files are held
// to the same bar so the package tree lifts out whole.
func TestImportBoundary(t *testing.T) {
	const hostModule = "github.com/sd-strax/reckon/"
	const selfPrefix = hostModule + "knowledge/substrate"

	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			ip := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(ip, hostModule) && !strings.HasPrefix(ip, selfPrefix) {
				t.Errorf("%s imports host package %q — the substrate must stay host-free (00-substrate §12)", path, ip)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
