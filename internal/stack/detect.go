// Package stack identifies which tech stacks a target folder uses.
package stack

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxDepth    = 3
	maxManifest = 1 << 20 // a manifest is read this far; past that it counts as malformed or no match
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".next": true, "dist": true,
	"build": true, "vendor": true, ".venv": true, "__pycache__": true,
}

var pythonManifests = map[string]bool{
	"requirements.txt": true, "pyproject.toml": true, "uv.lock": true, "poetry.lock": true,
}

// Detect returns the sorted stack IDs (fastapi, nextjs, php, react, supabase, web3) found under root.
func Detect(root string) ([]string, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}

	found := map[string]bool{}
	if isDir(filepath.Join(root, "supabase", "migrations")) || isFile(filepath.Join(root, "supabase", "config.toml")) {
		found["supabase"] = true
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if path == root {
				return werr
			}
			return nil // unreadable entries are skipped
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if path == root {
				return nil
			}
			if skipDirs[d.Name()] || len(strings.Split(filepath.ToSlash(rel), "/")) > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() { // a link could point at /dev/zero, a FIFO at nothing
			return nil
		}
		switch name := d.Name(); {
		case name == "package.json":
			checkPackageJSON(path, found)
		case name == "composer.json", strings.HasSuffix(name, ".php"), strings.HasSuffix(name, ".phtml"):
			found["php"] = true
		case pythonManifests[name]:
			if hasFastAPI(path) {
				found["fastapi"] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(found))
	for id := range found {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

func isDir(p string) bool  { i, err := os.Stat(p); return err == nil && i.IsDir() }
func isFile(p string) bool { i, err := os.Stat(p); return err == nil && i.Mode().IsRegular() }

func checkPackageJSON(path string, found map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxManifest))
	if err != nil {
		return
	}
	var pkg struct {
		Dependencies    map[string]json.RawMessage `json:"dependencies"`
		DevDependencies map[string]json.RawMessage `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return // malformed: skip
	}
	_, nextDep := pkg.Dependencies["next"]
	_, nextDev := pkg.DevDependencies["next"]
	for _, deps := range []map[string]json.RawMessage{pkg.Dependencies, pkg.DevDependencies} {
		if _, ok := deps["next"]; ok {
			found["nextjs"] = true
		}
		// A Next.js package has react too, but Next.js builds only NEXT_PUBLIC_
		// variables into browser code, so the VITE_ and REACT_APP_ rules don't fit.
		if _, ok := deps["react"]; ok && !nextDep && !nextDev {
			found["react"] = true
		}
		if _, ok := deps["@supabase/supabase-js"]; ok {
			found["supabase"] = true
		}
		for name := range deps {
			if isWeb3Package(name) {
				found["web3"] = true
			}
		}
	}
}

func hasFastAPI(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, maxManifest))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.ToLower(sc.Text())
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		if lineHasFastAPI(line) {
			return true
		}
	}
	return false // a scan error (e.g. overlong line) is treated as no match
}

// lineHasFastAPI reports whether line contains the package name "fastapi" at
// token boundaries, so "fastapi-utils" does not match.
func lineHasFastAPI(line string) bool {
	const name = "fastapi"
	for off := 0; ; {
		j := strings.Index(line[off:], name)
		if j < 0 {
			return false
		}
		start, end := off+j, off+j+len(name)
		beforeOK := start == 0 || strings.ContainsRune("\"', \t[(=", rune(line[start-1]))
		afterOK := end == len(line) || strings.ContainsRune("[=<>~!\"',;] \t", rune(line[end]))
		if beforeOK && afterOK {
			return true
		}
		off = end
	}
}

// isWeb3Package reports the packages that make a project a web3 one: ethers,
// viem, web3, hardhat, @wagmi/core and anything under @safe-global/ or
// @ethersproject/ (ethers v5's own packages). Similar names (web3-utils,
// ethers-lite, hardhat-gas-reporter) don't count.
func isWeb3Package(name string) bool {
	switch name {
	case "ethers", "viem", "web3", "hardhat", "@wagmi/core":
		return true
	}
	for _, scope := range []string{"@safe-global/", "@ethersproject/"} {
		if strings.HasPrefix(name, scope) && len(name) > len(scope) {
			return true
		}
	}
	return false
}
