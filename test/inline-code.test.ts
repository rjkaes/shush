import { describe, expect, test } from "bun:test";
import { bash } from "./eval-helpers";

// ==============================================================================
// Python -c
// ==============================================================================

describe("python -c safe payloads → package_run (allow)", () => {
  const safe = [
    `python3 -c "import json; print(json.dumps({'a': 1}))"`,
    `python -c "import json; print(json.dumps({'key': 'val'}, indent=2))"`,
    `python3 -c "import sys; print(sys.version)"`,
    `python3 -c "import pathlib; print(pathlib.Path('x').resolve())"`,
    `python3 -c "print('hello'.upper())"`,
    `python3 -c "import math; print(math.sqrt(2))"`,
    `python3 -c "import re; print(re.match(r'\\d+', '42').group())"`,
    `python3 -c "import base64; print(base64.b64encode(b'test'))"`,
    `python3 -c "import hashlib; print(hashlib.sha256(b'test').hexdigest())"`,
    `python3 -c "import collections; print(collections.Counter([1,2,2,3]))"`,
    `python3 -c "import datetime; print(datetime.datetime.now().isoformat())"`,
    `python3 -c "import textwrap; print(textwrap.fill('hello world', 5))"`,
    `python3 -c "import pprint; pprint.pprint({'a': 1})"`,
    `python3 -c "import os.path; print(os.path.join('a', 'b'))"`,
    `python3 -c "from json import dumps; print(dumps([1,2,3]))"`,
    `python3 -c "from pathlib import Path; print(Path.cwd())"`,
    `python3 -c "from collections import defaultdict; d = defaultdict(list)"`,
    `python3 -c "import uuid; print(uuid.uuid4())"`,
    `python3 -c "import csv; import io; r = csv.reader(io.StringIO('a,b'))"`,
    `python3 -c "print(len('hello'))"`,
    `python3 -c "x = [1,2,3]; print(sum(x))"`,
    `python3 -c "import string; print(string.ascii_lowercase)"`,
    `python3 -c "import itertools; print(list(itertools.chain([1],[2])))"`,
    `python3 -c "import functools; print(functools.reduce(lambda a,b: a+b, [1,2]))"`,
    `python3 -c "import typing; print(typing.get_type_hints)"`,
    `python3 -c "import enum; print(enum.Enum)"`,
    `python3 -c "import dataclasses; print(dataclasses.field)"`,
    `python3 -c "import xml.etree.ElementTree as ET; print(ET)"`,
  ];

  for (const cmd of safe) {
    test(cmd, () => {
      expect(bash(cmd).decision).toBe("allow");
    });
  }
});

describe("python -c dangerous payloads → lang_exec (ask)", () => {
  const dangerous = [
    // Dangerous imports
    [`python3 -c "import subprocess; subprocess.run(['ls'])"`, "subprocess"],
    [`python3 -c "import shutil; shutil.rmtree('/tmp/x')"`, "shutil"],
    [`python3 -c "import os; os.system('whoami')"`, "os.system"],
    [`python3 -c "import os; os.remove('/tmp/x')"`, "os.remove"],
    [`python3 -c "import urllib.request; urllib.request.urlopen('http://evil')"`, "urllib"],
    [`python3 -c "import http.client; http.client.HTTPConnection('evil')"`, "http.client"],
    [`python3 -c "import socket; socket.socket()"`, "socket"],
    // Dangerous builtins
    [`python3 -c "eval('1+1')"`, "eval()"],
    [`python3 -c "exec('print(1)')"`, "exec()"],
    [`python3 -c "compile('1+1', '<string>', 'eval')"`, "compile()"],
    [`python3 -c "__import__('os').system('whoami')"`, "__import__"],
    // open() for file mutation
    [`python3 -c "open('/tmp/x', 'w').write('pwned')"`, "open()"],
    // Reflection
    [`python3 -c "getattr(__builtins__, 'eval')('1+1')"`, "getattr"],
    // Variable expansion (can't see actual code)
    [`python3 -c "$CMD"`, "variable expansion"],
    // Backtick in payload
    ["python3 -c \"`echo hi`\"", "backtick"],
  ];

  for (const [cmd, reason] of dangerous) {
    test(`${reason}: ${cmd}`, () => {
      expect(bash(cmd).decision).toBe("ask");
    });
  }
});

describe("python -c unknown imports → lang_exec (ask)", () => {
  const unknown = [
    `python3 -c "import boto3; print(boto3.__version__)"`,
    `python3 -c "import flask; app = flask.Flask(__name__)"`,
    `python3 -c "import numpy as np; print(np.array([1,2,3]))"`,
    `python3 -c "import requests; requests.get('http://evil')"`,
  ];

  for (const cmd of unknown) {
    test(cmd, () => {
      expect(bash(cmd).decision).toBe("ask");
    });
  }
});

// ==============================================================================
// Node -e
// ==============================================================================

describe("node -e safe payloads → package_run (allow)", () => {
  const safe = [
    `node -e "console.log(JSON.parse('{\"a\":1}'))"`,
    `node -e "console.log(JSON.stringify({a:1}, null, 2))"`,
    `node -e "console.log(process.version)"`,
    `node -e "console.log(process.env.HOME)"`,
    `node -e "const p = require('path'); console.log(p.join('a','b'))"`,
    `node -e "console.log(Buffer.from('test').toString('base64'))"`,
    `node -e "console.log(require('os').platform())"`,
    `node -e "console.log(require('url').parse('http://x.com'))"`,
    `node -e "console.log(require('util').format('%s', 'hi'))"`,
    `node -e "console.log(require('crypto').randomUUID())"`,
    `node -e "console.log(1 + 2)"`,
    `node -e "const x = [1,2,3]; console.log(x.map(n => n*2))"`,
    `node -e "console.log(require('querystring').stringify({a:1}))"`,
    `node -e "console.log(require('assert').ok(true))"`,
  ];

  for (const cmd of safe) {
    test(cmd, () => {
      expect(bash(cmd).decision).toBe("allow");
    });
  }
});

describe("node -e dangerous payloads → lang_exec (ask)", () => {
  const dangerous = [
    [`node -e "require('child_process').execSync('whoami')"`, "child_process"],
    [`node -e "require('fs').writeFileSync('/tmp/x', 'pwned')"`, "fs"],
    [`node -e "require('net').createServer()"`, "net"],
    [`node -e "require('http').createServer()"`, "http"],
    [`node -e "require('https').get('https://evil')"`, "https"],
    [`node -e "require('dns').resolve('evil.com')"`, "dns"],
    [`node -e "eval('console.log(1)')"`, "eval()"],
    [`node -e "new Function('return 1')()"`, "Function()"],
    [`node -e "import('fs').then(m => m.writeFileSync('/tmp/x','y'))"`, "dynamic import"],
    // Variable expansion
    [`node -e "$CODE"`, "variable expansion"],
  ];

  for (const [cmd, reason] of dangerous) {
    test(`${reason}: ${cmd}`, () => {
      expect(bash(cmd).decision).toBe("ask");
    });
  }
});

// ==============================================================================
// Bun -e
// ==============================================================================

describe("bun -e safe payloads → package_run (allow)", () => {
  const safe = [
    `bun -e "console.log(JSON.parse('{\"a\":1}'))"`,
    `bun -e "console.log(JSON.stringify({a:1}, null, 2))"`,
    `bun -e "console.log(process.version)"`,
    `bun -e "console.log(process.env.HOME)"`,
    `bun -e "const p = require('path'); console.log(p.join('a','b'))"`,
    `bun -e "console.log(Buffer.from('test').toString('base64'))"`,
    `bun -e "console.log(require('os').platform())"`,
    `bun -e "console.log(require('url').parse('http://x.com'))"`,
    `bun -e "console.log(require('util').format('%s', 'hi'))"`,
    `bun -e "console.log(require('crypto').randomUUID())"`,
    `bun -e "console.log(1 + 2)"`,
    `bun -e "const x = [1,2,3]; console.log(x.map(n => n*2))"`,
    // --eval long form
    `bun --eval "console.log(42)"`,
    `bun --eval "console.log(require('path').join('a','b'))"`,
  ];

  for (const cmd of safe) {
    test(cmd, () => {
      expect(bash(cmd).decision).toBe("allow");
    });
  }
});

describe("bun -e dangerous payloads → lang_exec (ask)", () => {
  const dangerous = [
    [`bun -e "require('child_process').execSync('whoami')"`, "child_process"],
    [`bun -e "require('fs').writeFileSync('/tmp/x', 'pwned')"`, "fs"],
    [`bun -e "require('net').createServer()"`, "net"],
    [`bun -e "require('http').createServer()"`, "http"],
    [`bun -e "require('https').get('https://evil')"`, "https"],
    [`bun -e "require('dns').resolve('evil.com')"`, "dns"],
    [`bun -e "eval('console.log(1)')"`, "eval()"],
    [`bun -e "new Function('return 1')()"`, "Function()"],
    [`bun -e "import('fs').then(m => m.writeFileSync('/tmp/x','y'))"`, "dynamic import"],
    // Variable expansion
    [`bun -e "$CODE"`, "variable expansion"],
    // --eval long form with dangerous payload
    [`bun --eval "require('child_process').execSync('whoami')"`, "--eval child_process"],
  ];

  for (const [cmd, reason] of dangerous) {
    test(`${reason}: ${cmd}`, () => {
      expect(bash(cmd).decision).toBe("ask");
    });
  }
});

// ==============================================================================
// Ruby -e
// ==============================================================================

describe("ruby -e safe payloads → package_run (allow)", () => {
  const safe = [
    `ruby -e "require 'json'; puts JSON.generate({a: 1})"`,
    `ruby -e "puts 'hello'.upcase"`,
    `ruby -e "require 'set'; s = Set.new([1,2,3]); puts s.to_a"`,
    `ruby -e "require 'date'; puts Date.today"`,
    `ruby -e "require 'pathname'; puts Pathname.new('.').realpath"`,
    `ruby -e "require 'base64'; puts Base64.encode64('test')"`,
    `ruby -e "require 'digest'; puts Digest::SHA256.hexdigest('test')"`,
    `ruby -e "require 'pp'; pp({a: 1, b: 2})"`,
    `ruby -e "require 'securerandom'; puts SecureRandom.uuid"`,
    `ruby -e "require 'yaml'; puts YAML.dump({a: 1})"`,
    `ruby -e "require 'csv'; puts CSV.generate { |c| c << [1,2] }"`,
    `ruby -e "puts [1,2,3].map { |n| n * 2 }"`,
  ];

  for (const cmd of safe) {
    test(cmd, () => {
      expect(bash(cmd).decision).toBe("allow");
    });
  }
});

describe("ruby -e dangerous payloads → lang_exec (ask)", () => {
  const dangerous = [
    [`ruby -e "system('whoami')"`, "system()"],
    [`ruby -e "exec('ls')"`, "exec()"],
    ["ruby -e \"puts `whoami`\"", "backtick"],
    [`ruby -e "IO.popen('ls') { |f| puts f.read }"`, "IO.popen"],
    [`ruby -e "require 'open3'; Open3.capture2('ls')"`, "Open3"],
    [`ruby -e "require 'net/http'; Net::HTTP.get(URI('http://evil'))"`, "Net::HTTP"],
    [`ruby -e "eval('puts 1')"`, "eval()"],
    [`ruby -e "send(:system, 'ls')"`, "send()"],
    [`ruby -e "File.write('/tmp/x', 'pwned')"`, "File.write"],
    [`ruby -e "FileUtils.rm_rf('/tmp/x')"`, "FileUtils"],
    // Variable expansion
    [`ruby -e "$CODE"`, "variable expansion"],
  ];

  for (const [cmd, reason] of dangerous) {
    test(`${reason}: ${cmd}`, () => {
      expect(bash(cmd).decision).toBe("ask");
    });
  }
});

// ==============================================================================
// Edge cases
// ==============================================================================

describe("inline code edge cases", () => {
  test("python with no -c flag → script_exec (context)", () => {
    // No -c flag, so classifyInlineCode returns null.
    // Trie returns unknown, then classifyScriptExec catches it.
    expect(bash("python3 script.py").decision).toBe("context");
  });

  test("python -c with no payload → falls through", () => {
    expect(bash("python3 -c").decision).toBe("ask");
  });

  test("perl -e is not handled (not in allowlist)", () => {
    // perl -e is not in INLINE_CODE_CMDS, so it falls through to trie
    expect(bash("perl -e 'print 42'").decision).toBe("ask");
  });

  test("php -r is not handled (not in allowlist)", () => {
    expect(bash("php -r 'echo 42;'").decision).toBe("ask");
  });

  test("no-import python one-liner is safe", () => {
    expect(bash(`python3 -c "print(42)"`).decision).toBe("allow");
  });

  test("no-require node one-liner is safe", () => {
    expect(bash(`node -e "console.log(42)"`).decision).toBe("allow");
  });

  test("no-require ruby one-liner is safe", () => {
    expect(bash(`ruby -e "puts 42"`).decision).toBe("allow");
  });

  test("no-require bun one-liner is safe", () => {
    expect(bash(`bun -e "console.log(42)"`).decision).toBe("allow");
  });

  test("bun --eval one-liner is safe", () => {
    expect(bash(`bun --eval "console.log(42)"`).decision).toBe("allow");
  });

  test("node --eval one-liner is safe", () => {
    expect(bash(`node --eval "console.log(42)"`).decision).toBe("allow");
  });
});

// ==============================================================================
// Script Execution (interpreter + script file → script_exec)
// ==============================================================================

describe("script_exec classification", () => {
  const scriptCases: [string, string][] = [
    ["node script.js", "script_exec"],
    ["node ./build.mjs", "script_exec"],
    ["node node_modules/esbuild/bin/esbuild --bundle", "script_exec"],
    ["python3 app.py", "script_exec"],
    ["ruby tool.rb", "script_exec"],
    ["perl script.pl", "script_exec"],
    ["php server.php", "script_exec"],
    ["bun run.ts", "script_exec"],
  ];

  for (const [cmd, expected] of scriptCases) {
    test(`${cmd} → ${expected} (context)`, () => {
      expect(bash(cmd).decision).toBe("context");
    });
  }

  test("node -e still classifies as inline code, not script_exec", () => {
    // Should be allow (package_run), not context (script_exec)
    expect(bash(`node -e "console.log(1)"`).decision).toBe("allow");
  });

  test("bare node (no script) stays unknown", () => {
    // unknown → ask
    expect(bash("node").decision).toBe("ask");
  });

  test("deno test still classifies as package_run (trie takes precedence)", () => {
    expect(bash("deno test").decision).toBe("allow");
  });

  test("python -m pytest still classifies as package_run (trie takes precedence)", () => {
    expect(bash("python -m pytest").decision).toBe("allow");
  });

  test("absolute path stays unknown (ask) — not project-local", () => {
    expect(bash("node /tmp/exploit.js").decision).toBe("ask");
  });

  test("absolute python path stays unknown (ask)", () => {
    expect(bash("python3 /var/scripts/run.py").decision).toBe("ask");
  });
});
