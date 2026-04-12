#!/bin/sh
# Run TLC model checker on all shush TLA+ specs.
# Requires: Java (OpenJDK), tla2tools.jar in this directory.
#
# Download tla2tools.jar:
#   curl -sL https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar -o tla/tla2tools.jar

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$DIR/tla2tools.jar"

if [ ! -f "$JAR" ]; then
    echo "tla2tools.jar not found. Downloading..."
    curl -sL "https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar" \
        -o "$JAR"
fi

JAVA="${JAVA:-java}"
if ! command -v "$JAVA" >/dev/null 2>&1; then
    # macOS homebrew fallback
    if [ -x /opt/homebrew/opt/openjdk/bin/java ]; then
        JAVA=/opt/homebrew/opt/openjdk/bin/java
    else
        echo "Java not found. Install OpenJDK." >&2
        exit 1
    fi
fi

SPECS="PathGuard BashGuard"
FAIL=0

for spec in $SPECS; do
    echo "=== Checking $spec ==="
    if "$JAVA" -XX:+UseParallelGC -cp "$JAR" tlc2.TLC "$DIR/$spec" -workers auto; then
        echo "--- $spec: PASS ---"
    else
        echo "--- $spec: FAIL ---"
        FAIL=1
    fi
    echo
done

exit $FAIL
