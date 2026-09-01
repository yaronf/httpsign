package httpsign

import (
	"strings"

	"github.com/sergi/go-diff/diffmatchpatch"
)

// characterDiff returns an inline diff using (++added++) and (~~deleted~~) markup.
// Same formatting as the old github.com/andreyvit/diff CharacterDiff helper.
func characterDiff(a, b string) string {
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(a, b, true)
	if len(diffs) > 2 {
		diffs = dmp.DiffCleanupSemantic(diffs)
		diffs = dmp.DiffCleanupEfficiency(diffs)
	}
	var bld strings.Builder
	for _, d := range diffs {
		switch d.Type {
		case diffmatchpatch.DiffInsert:
			bld.WriteString("(++")
			bld.WriteString(d.Text)
			bld.WriteString("++)")
		case diffmatchpatch.DiffDelete:
			bld.WriteString("(~~")
			bld.WriteString(d.Text)
			bld.WriteString("~~)")
		case diffmatchpatch.DiffEqual:
			bld.WriteString(d.Text)
		}
	}
	return bld.String()
}
