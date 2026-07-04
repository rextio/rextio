# Zipapp Executable Example

Packages the project as a single-file `.pyz` zipapp executable. The
entrypoint and name are preconfigured in `rextio.toml` (`[executable]`), so a
plain build produces the executable alongside the wheel. Requires a Rust
toolchain; the target machine needs a compatible Python interpreter.

```text
rextio check examples/zipapp_app
rextio build examples/zipapp_app --fallback=cpython
python examples/zipapp_app/dist/zipapp_demo.pyz 500000
```

What to look for:

- `zipapp_app.core.checksum` is accepted as a direct-Rust native candidate.
- The build writes `dist/zipapp_demo.pyz` next to the wheel.
- Native extensions are not imported from inside a zipapp, so the `.pyz`
  runs through the Python fallback wrappers by design - the same code, the
  correctness baseline. Install the wheel instead when you want the native
  speed path.

Compare performance (native wheel vs. the fallback the zipapp uses):

```text
rextio bench zipapp_app.core.checksum --project-root examples/zipapp_app
```

The bench ratio shows what the native path gains over the fallback that the
zipapp executes; numbers depend on the machine.
