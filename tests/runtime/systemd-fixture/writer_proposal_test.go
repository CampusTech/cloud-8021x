package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestProposedWriterSurvivesInheritedPythonOptimization(t *testing.T) {
	// Compile the exact held heredoc, but never execute its top-level image paths.
	// Execute only its extracted write loop/guard on a tiny anonymous test file.
	script := `
import ast, dis, os, sys, tempfile, types
from pathlib import Path
if sys.flags.optimize != 2: raise SystemExit('inherited optimization not exercised')
text = Path('r129-preparation-proposal.md').read_text()
source = text.split("<<'PYWRITE'\n",1)[1].split('\nPYWRITE',1)[0]
tree = ast.parse(source)
for level in (0,1,2):
 code = compile(source,'exact-proposed-writer','exec',optimize=level)
 if 'pwrite' not in code.co_names:
  raise SystemExit('optimization removed actual pwrite at level '+str(level))
if any(isinstance(n,ast.Assert) for n in ast.walk(tree)):
 raise SystemExit('optimizable safety assertion remains')
guards = [n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='require']
if len(guards)!=1: raise SystemExit('explicit failure guard absent')
loops = [n for n in ast.walk(tree) if isinstance(n,ast.For) and any(isinstance(c,ast.Call) and isinstance(c.func,ast.Attribute) and c.func.attr=='pwrite' for c in ast.walk(n))]
if len(loops)!=1: raise SystemExit('single bounded write loop absent')
loop = loops[0]
if not any(isinstance(n,ast.Assign) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=='pwrite' for n in loop.body):
 raise SystemExit('write is not a standalone assignment')
module = ast.Module(body=guards+[loop],type_ignores=[])
program = compile(ast.fix_missing_locations(module),'exact-held-write-loop','exec',optimize=-1)
widths = [4,16,4,16,16,16,16,4,16,4]
patches=[];offset=0
for width in widths:
 patches.append((offset,b'a'*width,b'b'*width));offset+=width
if offset!=112: raise SystemExit('synthetic write count changed')
with tempfile.TemporaryFile() as f:
 f.write(b'a'*256);f.flush()
 namespace={'os':os,'dst':f.fileno(),'patches':patches}
 exec(program,namespace)
 if os.pread(f.fileno(),256,0)!=b'b'*112+b'a'*144:
  raise SystemExit('optimized loop did not perform exactly112 writes')
 for accepted in (True,False):
  try: namespace['require'](accepted,'synthetic guard')
  except RuntimeError:
   if accepted: raise SystemExit('true guard rejected')
  else:
   if not accepted: raise SystemExit('false guard accepted under optimization')
 short=types.SimpleNamespace(pwrite=lambda fd,data,offset:len(data)-1)
 try: exec(program,{'os':short,'dst':f.fileno(),'patches':patches})
 except RuntimeError: pass
 else: raise SystemExit('short write accepted under optimization')
print('optimized=2; levels0/1/2 retain pwrite; explicit false/short-write guards reject; synthetic112-byte write exact; no real image accessed')
`
	cmd := exec.Command("python3", "-c", script)
	var env []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "PYTHONOPTIMIZE=") {
			env = append(env, value)
		}
	}
	cmd.Env = append(env, "PYTHONOPTIMIZE=2")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("held writer unsafe under inherited optimization: %v\n%s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)))
}
