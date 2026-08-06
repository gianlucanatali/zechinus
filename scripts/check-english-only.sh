#!/usr/bin/env bash
# Fails when Italian shows up anywhere in the package. zechinus ships on its own, so it
# speaks one language. The word list is a heuristic on common Italian function words —
# it won't catch everything, but it catches the way this actually happens: someone in a
# hurry writing a comment in the language they were thinking in.
set -uo pipefail
PATTERN='\b(che|perch[ée]|quindi|questo|questa|queste|questi|viene|deve|senza|anche|nella|della|sono|invece|siccome|oppure|prima di|non . |cifrat|chiave|stesso|ogni|solo se|va bene)\b'
HITS=$(grep -rniE "$PATTERN" --include="*.ts" --include="*.tsx" --include="*.md" --include="*.mjs" --include="*.js" . \
  | grep -v node_modules | grep -v '/dist' \
  | grep -v '/\.superpowers/' | grep -v '/\.worktrees/' || true)
if [ -n "$HITS" ]; then
  echo "ERROR: Italian found in zechinus (English-only package — see AGENTS.md rule 15):"
  echo "$HITS"
  exit 1
fi
echo "OK: English-only"
