import { describe, expect, test } from "bun:test";
import { bash } from "./eval-helpers";

describe("new filesystem_read entries", () => {
  const cases: [string, string][] = [
    ["jq '.name' package.json", "filesystem_read"],
    ["yq '.version' config.yaml", "filesystem_read"],
    ["fd '*.ts' src/", "filesystem_read"],
    ["ag TODO src/", "filesystem_read"],
    ["eza -la", "filesystem_read"],
    ["delta", "filesystem_read"],
    ["docker ps", "filesystem_read"],
    ["docker logs mycontainer", "filesystem_read"],
    ["docker compose ps", "filesystem_read"],
    ["docker compose logs app", "filesystem_read"],
    ["docker images", "filesystem_read"],
    ["docker info", "filesystem_read"],
    ["docker version", "filesystem_read"],
    ["docker stats", "filesystem_read"],
    ["docker history myimage", "filesystem_read"],
    ["docker network ls", "filesystem_read"],
    ["docker volume ls", "filesystem_read"],
    ["docker system df", "filesystem_read"],
    ["podman ps", "filesystem_read"],
    ["podman images", "filesystem_read"],
    ["podman logs mycontainer", "filesystem_read"],
    ["man git", "filesystem_read"],
    ["apropos search", "filesystem_read"],
    ["tldr git", "filesystem_read"],
    ["id", "filesystem_read"],
    ["groups", "filesystem_read"],
    ["printenv", "filesystem_read"],
    ["sw_vers", "filesystem_read"],
    ["otool -L /usr/bin/git", "filesystem_read"],
    ["nm libfoo.a", "filesystem_read"],
    ["ldd /usr/bin/git", "filesystem_read"],
    ["iconv -f utf-8 foo.txt", "filesystem_read"],
    ["jq", "filesystem_read"],
    ["xxd file.bin", "filesystem_read"],
    ["bc", "filesystem_read"],
    ["terraform show", "filesystem_read"],
    ["terraform output", "filesystem_read"],
    ["terraform validate", "filesystem_read"],
    ["terraform version", "filesystem_read"],
    ["helm list", "filesystem_read"],
    ["helm version", "filesystem_read"],
    ["helm status myrelease", "filesystem_read"],
    ["poetry show", "filesystem_read"],
    ["poetry --version", "filesystem_read"],
    ["pdm list", "filesystem_read"],
    ["hatch version", "filesystem_read"],
    ["deno --version", "filesystem_read"],
    ["deno info", "filesystem_read"],
    ["swift --version", "filesystem_read"],
    ["zig version", "filesystem_read"],
    ["flutter --version", "filesystem_read"],
    ["flutter doctor", "filesystem_read"],
    ["dart --version", "filesystem_read"],
    ["mix help", "filesystem_read"],
    ["sbt --version", "filesystem_read"],
    ["ruby --version", "filesystem_read"],
    ["bundle list", "filesystem_read"],
    ["rails --version", "filesystem_read"],
    ["bazel info", "filesystem_read"],
    ["bazel version", "filesystem_read"],
    ["bazel query //...", "filesystem_read"],
    ["defaults read com.apple.Finder", "filesystem_read"],
    ["launchctl list", "filesystem_read"],
    ["plutil -lint foo.plist", "filesystem_read"],
  ];

  for (const [cmd, expected] of cases) {
    test(`${cmd} → ${expected}`, () => {
      expect(bash(cmd).decision).toBe("allow");
    });
  }
});

describe("new package_run entries", () => {
  const cases: [string, string][] = [
    ["deno test", "package_run"],
    ["deno fmt", "package_run"],
    ["deno lint", "package_run"],
    ["deno run server.ts", "package_run"],
    ["deno check mod.ts", "package_run"],
    ["eslint src/", "package_run"],
    ["prettier --check .", "package_run"],
    ["tsc --noEmit", "package_run"],
    ["ruff check .", "package_run"],
    ["ruff format .", "package_run"],
    ["mypy src/", "package_run"],
    ["black --check .", "package_run"],
    ["pylint src/", "package_run"],
    ["flake8 src/", "package_run"],
    ["isort --check .", "package_run"],
    ["bandit -r src/", "package_run"],
    ["tox", "package_run"],
    ["nox", "package_run"],
    ["rubocop", "package_run"],
    ["rspec", "package_run"],
    ["rake", "package_run"],
    ["bundle exec rspec", "package_run"],
    ["rails test", "package_run"],
    ["rails server", "package_run"],
    ["mix test", "package_run"],
    ["mix compile", "package_run"],
    ["mix format", "package_run"],
    ["mix phx.server", "package_run"],
    ["zig build", "package_run"],
    ["zig test", "package_run"],
    ["zig fmt", "package_run"],
    ["swift build", "package_run"],
    ["swift test", "package_run"],
    ["swift run", "package_run"],
    ["flutter test", "package_run"],
    ["flutter build apk", "package_run"],
    ["flutter analyze", "package_run"],
    ["dart test", "package_run"],
    ["dart analyze", "package_run"],
    ["dart format .", "package_run"],
    ["dart compile exe main.dart", "package_run"],
    ["bazel build //...", "package_run"],
    ["bazel test //...", "package_run"],
    ["bazel run //:app", "package_run"],
    ["ninja", "package_run"],
    ["meson test", "package_run"],
    ["sbt test", "package_run"],
    ["sbt compile", "package_run"],
    ["lein test", "package_run"],
    ["lein run", "package_run"],
    ["cabal build", "package_run"],
    ["cabal test", "package_run"],
    ["stack build", "package_run"],
    ["stack test", "package_run"],
    ["vitest run", "package_run"],
    ["vitest", "package_run"],
    ["jest", "package_run"],
    ["mocha", "package_run"],
    ["biome check .", "package_run"],
    ["biome lint .", "package_run"],
    ["next build", "package_run"],
    ["next dev", "package_run"],
    ["vite build", "package_run"],
    ["turbo build", "package_run"],
    ["golangci-lint run", "package_run"],
    ["rustfmt src/main.rs", "package_run"],
    ["protoc --go_out=. foo.proto", "package_run"],
    ["buf lint", "package_run"],
    ["docker compose build", "package_run"],
    ["docker compose up", "package_run"],
    ["hatch run test", "package_run"],
    ["poetry run pytest", "package_run"],
    ["pdm run test", "package_run"],
    ["python -m unittest discover", "package_run"],
    ["python -m mypy src/", "package_run"],
    ["python -m ruff check .", "package_run"],
    ["python3 -m unittest discover", "package_run"],
    ["python3 -m black --check .", "package_run"],
    ["xcodebuild build", "package_run"],
    ["xcodebuild test", "package_run"],
  ];

  for (const [cmd, expected] of cases) {
    test(`${cmd} → ${expected} (allow)`, () => {
      expect(bash(cmd).decision).toBe("allow");
    });
  }
});

describe("new package_install entries", () => {
  const cases: string[] = [
    "poetry install",
    "poetry add flask",
    "poetry update",
    "pdm install",
    "pdm add requests",
    "bundle install",
    "bundle update",
    "mix deps.get",
    "mix deps.update --all",
    "terraform init",
    "helm repo add stable https://charts.helm.sh/stable",
    "deno install",
    "deno add npm:express",
    "cabal install",
    "stack setup",
    "flutter pub get",
    "dart pub get",
    "dart pub add http",
    "docker compose pull",
    "nix build",
  ];

  for (const cmd of cases) {
    test(`${cmd} → package_install (allow)`, () => {
      expect(bash(cmd).decision).toBe("allow");
    });
  }
});

describe("new package_uninstall entries", () => {
  const cases: string[] = [
    "docker compose down",
    "flutter clean",
    "bazel clean",
    "terraform destroy",
    "helm repo remove stable",
    "deno remove npm:express",
    "bundle clean",
    "cabal clean",
    "stack clean",
  ];

  for (const cmd of cases) {
    test(`${cmd} → package_uninstall (ask)`, () => {
      expect(bash(cmd).decision).toBe("ask");
    });
  }
});

describe("new process_signal entries", () => {
  const cases: string[] = [
    "docker stop mycontainer",
    "docker kill mycontainer",
    "docker restart mycontainer",
    "docker compose stop",
    "docker compose restart",
    "podman stop mycontainer",
    "podman kill mycontainer",
  ];

  for (const cmd of cases) {
    test(`${cmd} → process_signal (ask)`, () => {
      expect(bash(cmd).decision).toBe("ask");
    });
  }
});

describe("new network_write entries", () => {
  test("docker push → network_write (ask)", () => {
    expect(bash("docker push myimage:latest").decision).toBe("ask");
  });
});

describe("new container_destructive entries", () => {
  const cases: string[] = [
    "docker container prune",
    "docker image prune",
    "docker volume prune",
    "terraform apply",
  ];

  for (const cmd of cases) {
    test(`${cmd} → container_destructive (ask)`, () => {
      expect(bash(cmd).decision).toBe("ask");
    });
  }
});

describe("new db_read entries", () => {
  const cases: string[] = [
    "kubectl auth can-i get pods",
    "kubectl diff -f deployment.yaml",
    "kubectl rollout status deployment/app",
    "kubectl rollout history deployment/app",
  ];

  for (const cmd of cases) {
    test(`${cmd} → db_read (allow)`, () => {
      expect(bash(cmd).decision).toBe("allow");
    });
  }
});
