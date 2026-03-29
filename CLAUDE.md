# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

`nap` is the TypeScript monorepo for the NAP v2 packages.

## Build Commands

```bash
npm test
npm run typecheck
```

## Repository Structure

```text
nap/
└── packages/*
```

## Design Notes

- Keep protocol types portable across browser and server runtimes.
- Preserve package boundaries inside `packages/*`.
- Favor additive protocol changes and cross-package compatibility.
