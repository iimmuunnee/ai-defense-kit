package secrets

import (
	"strings"
	"testing"
)

// historyRepo has a secret only in the first of two commits. first may add files
// to that commit.
func historyRepo(t *testing.T, first func(root string)) string {
	t.Helper()
	root := t.TempDir()
	git(t, root, "init", "-q")
	if first != nil {
		first(root)
	}
	write(t, root, "config.js", "k = \""+fakeToken+"\"\n")
	git(t, root, "add", ".")
	git(t, root, "commit", "-qm", "one")
	write(t, root, "config.js", "k = 1\n")
	git(t, root, "add", ".")
	git(t, root, "commit", "-qm", "two")
	return root
}

// Each form keeps a secret out of git's patch text, or out of what gitleaks can
// read of it. hides says the form does so without the flag; the prefix settings
// were tried and hide nothing, and are kept here so that a new git would show.
func TestSecretsUntrustedReadsHistoryRepoSettingsHide(t *testing.T) {
	needGit(t)
	attrs := func(body string) func(root string) {
		return func(root string) { write(t, root, ".gitattributes", body) }
	}
	config := func(key, value string) func(t *testing.T, root string) {
		return func(t *testing.T, root string) { git(t, root, "config", key, value) }
	}
	cases := []struct {
		name  string
		first func(root string)
		after func(t *testing.T, root string)
		hides bool
	}{
		{name: "committed -diff", first: attrs("*.js -diff\n"), hides: true},
		{name: "committed binary", first: attrs("config.js binary\n"), hides: true},
		{name: "working tree -diff", after: func(t *testing.T, root string) { write(t, root, ".gitattributes", "*.js -diff\n") }, hides: true},
		{name: "working tree binary", after: func(t *testing.T, root string) { write(t, root, ".gitattributes", "config.js binary\n") }, hides: true},
		{name: "info/attributes", after: func(t *testing.T, root string) { write(t, root, ".git/info/attributes", "*.js -diff\n") }, hides: true},
		{name: "core.attributesFile", after: func(t *testing.T, root string) {
			write(t, root, "attrs", "*.js -diff\n")
			git(t, root, "config", "core.attributesFile", "attrs")
		}, hides: true},
		{name: "diff driver binary", first: attrs("*.js diff=x\n"), after: config("diff.x.binary", "true"), hides: true},
		{name: "core.bigFileThreshold", after: config("core.bigFileThreshold", "1"), hides: true},
		{name: "replace ref", after: func(t *testing.T, root string) {
			head := strings.TrimSpace(gitOut(t, root, "", "rev-parse", "HEAD"))
			clean := strings.TrimSpace(gitOut(t, root, "", "commit-tree", "HEAD^{tree}", "-m", "x"))
			git(t, root, "replace", head, clean)
		}, hides: true},
		{name: "color.ui", after: config("color.ui", "always"), hides: true},
		{name: "color.diff", after: config("color.diff", "always"), hides: true},
		{name: "log.showRoot", after: config("log.showRoot", "false"), hides: true},
		{name: "diff.noprefix", after: config("diff.noprefix", "true")},
		{name: "diff.mnemonicPrefix", after: config("diff.mnemonicPrefix", "true")},
		{name: "diff.srcPrefix", after: config("diff.srcPrefix", "x/")},
		{name: "diff.dstPrefix", after: config("diff.dstPrefix", "y/")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := historyRepo(t, c.first)
			if c.after != nil {
				c.after(t, root)
			}
			plain := run(t, root)
			if found := len(plain.Findings) != 0; found == c.hides {
				t.Errorf("control: hides=%v without the flag, got %v", c.hides, kinds(plain))
			}
			res := runUntrusted(t, root)
			if len(res.Findings) != 1 || res.Findings[0].Kind != "secret-history" {
				t.Errorf("untrusted: got %v, warnings %v", kinds(res), res.Warnings)
			}
		})
	}
}

// The flag changes nothing for a repository that hides nothing.
func TestSecretsUntrustedBaseline(t *testing.T) {
	needGit(t)
	root := historyRepo(t, nil)
	if res := run(t, root); len(res.Findings) != 1 {
		t.Errorf("baseline: got %v", kinds(res))
	}
	if res := runUntrusted(t, root); len(res.Findings) != 1 {
		t.Errorf("baseline untrusted: got %v", kinds(res))
	}
}
