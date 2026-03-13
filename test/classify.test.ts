import { describe, expect, test } from "bun:test";
import { classifyWithFlags } from "../src/classify";

describe("git flag classifier", () => {
  test("git push → git_write", () => {
    expect(classifyWithFlags(["git", "push"])).toBe("git_write");
  });
  test("git push --force → git_history_rewrite", () => {
    expect(classifyWithFlags(["git", "push", "--force"])).toBe("git_history_rewrite");
  });
  test("git push -f → git_history_rewrite", () => {
    expect(classifyWithFlags(["git", "push", "-f"])).toBe("git_history_rewrite");
  });
  test("git reset --hard → git_discard", () => {
    expect(classifyWithFlags(["git", "reset", "--hard"])).toBe("git_discard");
  });
  test("git reset → git_write", () => {
    expect(classifyWithFlags(["git", "reset"])).toBe("git_write");
  });
  test("git branch -d → git_discard", () => {
    expect(classifyWithFlags(["git", "branch", "-d", "feature"])).toBe("git_discard");
  });
  test("git branch -D → git_history_rewrite", () => {
    expect(classifyWithFlags(["git", "branch", "-D", "feature"])).toBe("git_history_rewrite");
  });
  test("git branch (list) → git_safe", () => {
    expect(classifyWithFlags(["git", "branch"])).toBe("git_safe");
  });
  test("git checkout . → git_discard", () => {
    expect(classifyWithFlags(["git", "checkout", "."])).toBe("git_discard");
  });
  test("git add --dry-run → git_safe", () => {
    expect(classifyWithFlags(["git", "add", "--dry-run"])).toBe("git_safe");
  });
  test("git clean → git_history_rewrite", () => {
    expect(classifyWithFlags(["git", "clean"])).toBe("git_history_rewrite");
  });
  test("git clean -n → git_safe", () => {
    expect(classifyWithFlags(["git", "clean", "-n"])).toBe("git_safe");
  });
  test("strips git -C flag", () => {
    expect(classifyWithFlags(["git", "-C", "/tmp", "status"])).toBe("git_safe");
  });
});

describe("git flag classifier — additional subcommands", () => {
  test("git tag (no args) → git_safe", () => {
    expect(classifyWithFlags(["git", "tag"])).toBe("git_safe");
  });
  test("git tag v1.0 → git_write", () => {
    expect(classifyWithFlags(["git", "tag", "v1.0"])).toBe("git_write");
  });
  test("git config --get → git_safe", () => {
    expect(classifyWithFlags(["git", "config", "--get", "user.name"])).toBe("git_safe");
  });
  test("git config --list → git_safe", () => {
    expect(classifyWithFlags(["git", "config", "--list"])).toBe("git_safe");
  });
  test("git config user.name (read) → git_safe", () => {
    expect(classifyWithFlags(["git", "config", "user.name"])).toBe("git_safe");
  });
  test("git config user.name 'value' (write) → git_write", () => {
    expect(classifyWithFlags(["git", "config", "user.name", "John"])).toBe("git_write");
  });
  test("git config --unset → git_write", () => {
    expect(classifyWithFlags(["git", "config", "--unset", "user.name"])).toBe("git_write");
  });
  test("git push +refspec → git_history_rewrite", () => {
    expect(classifyWithFlags(["git", "push", "origin", "+main"])).toBe("git_history_rewrite");
  });
  test("git push --force-with-lease → git_history_rewrite", () => {
    expect(classifyWithFlags(["git", "push", "--force-with-lease"])).toBe("git_history_rewrite");
  });
  test("git rm file → git_discard", () => {
    expect(classifyWithFlags(["git", "rm", "file.txt"])).toBe("git_discard");
  });
  test("git rm --cached → git_write", () => {
    expect(classifyWithFlags(["git", "rm", "--cached", "file.txt"])).toBe("git_write");
  });
  test("git reflog → git_safe", () => {
    expect(classifyWithFlags(["git", "reflog"])).toBe("git_safe");
  });
  test("git reflog delete → git_discard", () => {
    expect(classifyWithFlags(["git", "reflog", "delete"])).toBe("git_discard");
  });
  test("git reflog expire → git_discard", () => {
    expect(classifyWithFlags(["git", "reflog", "expire"])).toBe("git_discard");
  });
  test("git switch --discard-changes → git_discard", () => {
    expect(classifyWithFlags(["git", "switch", "--discard-changes"])).toBe("git_discard");
  });
  test("git switch branch → git_write", () => {
    expect(classifyWithFlags(["git", "switch", "feature"])).toBe("git_write");
  });
  test("git restore file → git_discard", () => {
    expect(classifyWithFlags(["git", "restore", "file.txt"])).toBe("git_discard");
  });
  test("git restore --staged → git_write", () => {
    expect(classifyWithFlags(["git", "restore", "--staged", "file.txt"])).toBe("git_write");
  });
  test("git log → git_safe (safe subcommand)", () => {
    expect(classifyWithFlags(["git", "log"])).toBe("git_safe");
  });
  test("git diff → git_safe (safe subcommand)", () => {
    expect(classifyWithFlags(["git", "diff"])).toBe("git_safe");
  });
  test("git add file → git_write", () => {
    expect(classifyWithFlags(["git", "add", "file.txt"])).toBe("git_write");
  });
  test("git add -n → git_safe", () => {
    expect(classifyWithFlags(["git", "add", "-n"])).toBe("git_safe");
  });
  test("git clean --dry-run → git_safe", () => {
    expect(classifyWithFlags(["git", "clean", "--dry-run"])).toBe("git_safe");
  });
  test("git branch -a → git_safe", () => {
    expect(classifyWithFlags(["git", "branch", "-a"])).toBe("git_safe");
  });
  test("git branch -vv → git_safe", () => {
    expect(classifyWithFlags(["git", "branch", "-vv"])).toBe("git_safe");
  });
  test("git checkout -B → git_discard", () => {
    expect(classifyWithFlags(["git", "checkout", "-B", "branch"])).toBe("git_discard");
  });
});

describe("git global flag stripping", () => {
  test("strips --no-pager", () => {
    expect(classifyWithFlags(["git", "--no-pager", "log"])).toBe("git_safe");
  });
  test("strips --git-dir", () => {
    expect(classifyWithFlags(["git", "--git-dir", "/tmp/.git", "status"])).toBe("git_safe");
  });
  test("strips --work-tree", () => {
    expect(classifyWithFlags(["git", "--work-tree", "/tmp", "diff"])).toBe("git_safe");
  });
  test("strips -c config", () => {
    expect(classifyWithFlags(["git", "-c", "core.pager=less", "log"])).toBe("git_safe");
  });
  test("strips --bare", () => {
    expect(classifyWithFlags(["git", "--bare", "log"])).toBe("git_safe");
  });
  test("strips multiple global flags", () => {
    expect(classifyWithFlags(["git", "--no-pager", "-C", "/tmp", "push", "--force"])).toBe("git_history_rewrite");
  });
})
describe("curl flag classifier", () => {
  test("curl url → network_outbound", () => {
    expect(classifyWithFlags(["curl", "https://example.com"])).toBe("network_outbound");
  });
  test("curl -X POST → network_write", () => {
    expect(classifyWithFlags(["curl", "-X", "POST", "https://example.com"])).toBe("network_write");
  });
  test("curl --data → network_write", () => {
    expect(classifyWithFlags(["curl", "--data", "foo", "https://example.com"])).toBe("network_write");
  });
  test("curl -d → network_write", () => {
    expect(classifyWithFlags(["curl", "-d", "foo", "https://example.com"])).toBe("network_write");
  });
});

describe("curl flag classifier — additional flags", () => {
  test("curl --data=foo → network_write", () => {
    expect(classifyWithFlags(["curl", "--data=foo", "https://example.com"])).toBe("network_write");
  });
  test("curl --json={} → network_write", () => {
    expect(classifyWithFlags(["curl", "--json={}", "https://example.com"])).toBe("network_write");
  });
  test("curl -F field=val → network_write", () => {
    expect(classifyWithFlags(["curl", "-F", "field=val", "https://example.com"])).toBe("network_write");
  });
  test("curl --form field=val → network_write", () => {
    expect(classifyWithFlags(["curl", "--form", "field=val", "https://example.com"])).toBe("network_write");
  });
  test("curl -T file → network_write", () => {
    expect(classifyWithFlags(["curl", "-T", "file.txt", "https://example.com"])).toBe("network_write");
  });
  test("curl --upload-file=f → network_write", () => {
    expect(classifyWithFlags(["curl", "--upload-file=f", "https://example.com"])).toBe("network_write");
  });
  test("curl --request=POST → network_write", () => {
    expect(classifyWithFlags(["curl", "--request=POST", "https://example.com"])).toBe("network_write");
  });
  test("curl --request=GET → network_outbound", () => {
    expect(classifyWithFlags(["curl", "--request=GET", "https://example.com"])).toBe("network_outbound");
  });
  test("curl -sXPOST → network_write (combined short flags)", () => {
    expect(classifyWithFlags(["curl", "-sXPOST", "https://example.com"])).toBe("network_write");
  });
  test("curl -X DELETE → network_write", () => {
    expect(classifyWithFlags(["curl", "-X", "DELETE", "https://example.com"])).toBe("network_write");
  });
  test("curl -X GET → network_outbound", () => {
    expect(classifyWithFlags(["curl", "-X", "GET", "https://example.com"])).toBe("network_outbound");
  });
})
describe("find flag classifier", () => {
  test("find . → filesystem_read", () => {
    expect(classifyWithFlags(["find", "."])).toBe("filesystem_read");
  });
  test("find -delete → filesystem_delete", () => {
    expect(classifyWithFlags(["find", ".", "-delete"])).toBe("filesystem_delete");
  });
  test("find -exec rm → filesystem_delete", () => {
    expect(classifyWithFlags(["find", ".", "-exec", "rm", "{}", ";"])).toBe("filesystem_delete");
  });
  test("find -exec grep → filesystem_read", () => {
    expect(classifyWithFlags(["find", ".", "-type", "f", "-exec", "grep", "-l", "pattern", "{}", "+"])).toBe("filesystem_read");
  });
  test("find -execdir cat → filesystem_read", () => {
    expect(classifyWithFlags(["find", ".", "-execdir", "cat", "{}", ";"])).toBe("filesystem_read");
  });
  test("find -exec sed -i → filesystem_write", () => {
    expect(classifyWithFlags(["find", ".", "-exec", "sed", "-i", "s/a/b/", "{}", ";"])).toBe("filesystem_write");
  });
  test("find -exec with no command → filesystem_delete (conservative)", () => {
    expect(classifyWithFlags(["find", ".", "-exec"])).toBe("filesystem_delete");
  });
});

describe("find flag classifier — additional actions", () => {
  test("find -ok rm → filesystem_delete", () => {
    expect(classifyWithFlags(["find", ".", "-ok", "rm", "{}", ";"])).toBe("filesystem_delete");
  });
  test("find -execdir sed -i → filesystem_write", () => {
    expect(classifyWithFlags(["find", ".", "-execdir", "sed", "-i", "s/a/b/", "{}", ";"])).toBe("filesystem_write");
  });
})
describe("sed flag classifier", () => {
  test("sed (read) → filesystem_read", () => {
    expect(classifyWithFlags(["sed", "s/a/b/"])).toBe("filesystem_read");
  });
  test("sed -i → filesystem_write", () => {
    expect(classifyWithFlags(["sed", "-i", "s/a/b/", "file"])).toBe("filesystem_write");
  });
});

describe("sed flag classifier — additional variants", () => {
  test("sed -I (BSD uppercase) → filesystem_write", () => {
    expect(classifyWithFlags(["sed", "-I", "s/a/b/", "file"])).toBe("filesystem_write");
  });
  test("sed --in-place → filesystem_write", () => {
    expect(classifyWithFlags(["sed", "--in-place", "s/a/b/", "file"])).toBe("filesystem_write");
  });
  test("sed --in-place=.bak → filesystem_write", () => {
    expect(classifyWithFlags(["sed", "--in-place=.bak", "s/a/b/", "file"])).toBe("filesystem_write");
  });
  test("sed -ni → filesystem_write (combined flags)", () => {
    expect(classifyWithFlags(["sed", "-ni", "s/a/b/", "file"])).toBe("filesystem_write");
  });
  test("sed -ein → filesystem_write (combined flags with i)", () => {
    expect(classifyWithFlags(["sed", "-ein", "s/a/b/", "file"])).toBe("filesystem_write");
  });
})
describe("non-flag commands return null", () => {
  test("ls returns null (use prefix table)", () => {
    expect(classifyWithFlags(["ls"])).toBeNull();
  });
});

describe("awk flag classifier", () => {
  test("awk '{print}' → null (no dangerous patterns)", () => {
    expect(classifyWithFlags(["awk", "{print}"])).toBeNull();
  });
  test("awk with system() → lang_exec", () => {
    expect(classifyWithFlags(["awk", '{system("rm -rf /")}'])).toBe("lang_exec");
  });
  test("awk with | getline → lang_exec", () => {
    expect(classifyWithFlags(["awk", '{"date" | getline d}'])).toBe("lang_exec");
  });
  test("awk with print > → lang_exec", () => {
    expect(classifyWithFlags(["awk", '{print > "file"}'])).toBe("lang_exec");
  });
  test("gawk with system() → lang_exec", () => {
    expect(classifyWithFlags(["gawk", '{system("ls")}'])).toBe("lang_exec");
  });
  test("mawk with |& → lang_exec", () => {
    expect(classifyWithFlags(["mawk", '{print |& "cmd"}'])).toBe("lang_exec");
  });
  test("nawk safe → null", () => {
    expect(classifyWithFlags(["nawk", '/pattern/ {print $1}'])).toBeNull();
  });
  test("awk skips flags before checking patterns", () => {
    expect(classifyWithFlags(["awk", "-F:", '{system("id")}'])).toBe("lang_exec");
  });
});

describe("tar flag classifier", () => {
  test("tar tf archive → filesystem_read", () => {
    expect(classifyWithFlags(["tar", "tf", "archive.tar"])).toBe("filesystem_read");
  });
  test("tar xf archive → filesystem_write", () => {
    expect(classifyWithFlags(["tar", "xf", "archive.tar"])).toBe("filesystem_write");
  });
  test("tar czf archive → filesystem_write", () => {
    expect(classifyWithFlags(["tar", "czf", "archive.tar.gz", "dir/"])).toBe("filesystem_write");
  });
  test("tar -tf archive → filesystem_read", () => {
    expect(classifyWithFlags(["tar", "-tf", "archive.tar"])).toBe("filesystem_read");
  });
  test("tar -xzf archive → filesystem_write", () => {
    expect(classifyWithFlags(["tar", "-xzf", "archive.tar.gz"])).toBe("filesystem_write");
  });
  test("tar --list → filesystem_read", () => {
    expect(classifyWithFlags(["tar", "--list", "-f", "archive.tar"])).toBe("filesystem_read");
  });
  test("tar --extract → filesystem_write", () => {
    expect(classifyWithFlags(["tar", "--extract", "-f", "archive.tar"])).toBe("filesystem_write");
  });
  test("tar --create → filesystem_write", () => {
    expect(classifyWithFlags(["tar", "--create", "-f", "archive.tar", "dir/"])).toBe("filesystem_write");
  });
  test("tar (no args) → filesystem_write (conservative)", () => {
    expect(classifyWithFlags(["tar"])).toBe("filesystem_write");
  });
  test("tar rf archive → filesystem_write (append)", () => {
    expect(classifyWithFlags(["tar", "rf", "archive.tar", "newfile"])).toBe("filesystem_write");
  });
  test("tar --append → filesystem_write", () => {
    expect(classifyWithFlags(["tar", "--append", "-f", "archive.tar", "newfile"])).toBe("filesystem_write");
  });
  test("tar --delete → filesystem_write", () => {
    expect(classifyWithFlags(["tar", "--delete", "-f", "archive.tar", "file"])).toBe("filesystem_write");
  });
});

describe("wget flag classifier", () => {
  test("wget url → network_outbound", () => {
    expect(classifyWithFlags(["wget", "https://example.com"])).toBe("network_outbound");
  });
  test("wget --post-data → network_write", () => {
    expect(classifyWithFlags(["wget", "--post-data", "key=val", "https://example.com"])).toBe("network_write");
  });
  test("wget --post-data=val → network_write", () => {
    expect(classifyWithFlags(["wget", "--post-data=key=val", "https://example.com"])).toBe("network_write");
  });
  test("wget --post-file → network_write", () => {
    expect(classifyWithFlags(["wget", "--post-file", "data.json", "https://example.com"])).toBe("network_write");
  });
  test("wget --post-file=data.json → network_write", () => {
    expect(classifyWithFlags(["wget", "--post-file=data.json", "https://example.com"])).toBe("network_write");
  });
  test("wget --method POST → network_write", () => {
    expect(classifyWithFlags(["wget", "--method", "POST", "https://example.com"])).toBe("network_write");
  });
  test("wget --method=DELETE → network_write", () => {
    expect(classifyWithFlags(["wget", "--method=DELETE", "https://example.com"])).toBe("network_write");
  });
  test("wget --method GET → network_outbound", () => {
    expect(classifyWithFlags(["wget", "--method", "GET", "https://example.com"])).toBe("network_outbound");
  });
  test("wget --method=GET → network_outbound", () => {
    expect(classifyWithFlags(["wget", "--method=GET", "https://example.com"])).toBe("network_outbound");
  });
});

describe("httpie flag classifier", () => {
  test("http url → network_outbound", () => {
    expect(classifyWithFlags(["http", "https://example.com"])).toBe("network_outbound");
  });
  test("http POST url → network_write", () => {
    expect(classifyWithFlags(["http", "POST", "https://example.com"])).toBe("network_write");
  });
  test("http PUT url → network_write", () => {
    expect(classifyWithFlags(["http", "PUT", "https://example.com"])).toBe("network_write");
  });
  test("http DELETE url → network_write", () => {
    expect(classifyWithFlags(["http", "DELETE", "https://example.com"])).toBe("network_write");
  });
  test("http GET url → network_outbound", () => {
    expect(classifyWithFlags(["http", "GET", "https://example.com"])).toBe("network_outbound");
  });
  test("https url → network_outbound", () => {
    expect(classifyWithFlags(["https", "https://example.com"])).toBe("network_outbound");
  });
  test("xh POST url → network_write", () => {
    expect(classifyWithFlags(["xh", "POST", "https://example.com"])).toBe("network_write");
  });
  test("xhs url → network_outbound", () => {
    expect(classifyWithFlags(["xhs", "https://example.com"])).toBe("network_outbound");
  });
  test("http url key=value → network_write (data item)", () => {
    expect(classifyWithFlags(["http", "https://example.com", "name=John"])).toBe("network_write");
  });
  test("http url key:=value → network_write (JSON data item)", () => {
    expect(classifyWithFlags(["http", "https://example.com", "count:=5"])).toBe("network_write");
  });
  test("http --form url → network_write", () => {
    expect(classifyWithFlags(["http", "--form", "https://example.com"])).toBe("network_write");
  });
  test("http -f url → network_write", () => {
    expect(classifyWithFlags(["http", "-f", "https://example.com"])).toBe("network_write");
  });
  test("http url file@path → network_write (file upload)", () => {
    expect(classifyWithFlags(["http", "https://example.com", "file@data.bin"])).toBe("network_write");
  });
});

describe("global install classifier", () => {
  test("npm install -g → unknown", () => {
    expect(classifyWithFlags(["npm", "install", "-g", "pkg"])).toBe("unknown");
  });
  test("npm install --global → unknown", () => {
    expect(classifyWithFlags(["npm", "install", "--global", "pkg"])).toBe("unknown");
  });
  test("pip install --system → unknown", () => {
    expect(classifyWithFlags(["pip", "install", "--system", "pkg"])).toBe("unknown");
  });
  test("pip3 install --target dir → unknown", () => {
    expect(classifyWithFlags(["pip3", "install", "--target", "/usr/local", "pkg"])).toBe("unknown");
  });
  test("cargo install --root /usr → unknown", () => {
    expect(classifyWithFlags(["cargo", "install", "--root", "/usr", "pkg"])).toBe("unknown");
  });
  test("gem install --system → unknown", () => {
    expect(classifyWithFlags(["gem", "install", "--system", "pkg"])).toBe("unknown");
  });
  test("bun install -g → unknown", () => {
    expect(classifyWithFlags(["bun", "install", "-g", "pkg"])).toBe("unknown");
  });
  test("pnpm install --global → unknown", () => {
    expect(classifyWithFlags(["pnpm", "install", "--global", "pkg"])).toBe("unknown");
  });
  test("npm install (local) → null", () => {
    expect(classifyWithFlags(["npm", "install", "pkg"])).toBeNull();
  });
  test("pip install (local) → null", () => {
    expect(classifyWithFlags(["pip", "install", "pkg"])).toBeNull();
  });
});

describe("edge cases", () => {
  test("empty tokens → null", () => {
    expect(classifyWithFlags([])).toBeNull();
  });
  test("unrecognized command → null", () => {
    expect(classifyWithFlags(["mysterycommand", "arg"])).toBeNull();
  });
})
