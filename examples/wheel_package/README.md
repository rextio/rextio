# Hybrid Wheel Example

Builds the default Rextio artifact: a pip-installable wheel that carries the
compiled native extension together with the Python fallback code, behind
unchanged import paths. Requires a Rust toolchain.

```text
rextio check examples/wheel_package
rextio build examples/wheel_package --fallback=cpython
```

Install the wheel into any environment and use the package normally:

```text
python -m venv /tmp/wheel-demo-venv
/tmp/wheel-demo-venv/bin/pip install examples/wheel_package/dist/*.whl
/tmp/wheel-demo-venv/bin/python -c "
from wheel_package.series import harmonic_like, window_max
print(harmonic_like(1000000))
print(window_max([3, 9, 4]))
"
```

What to look for:

- `wheel_package.series.harmonic_like` and `wheel_package.series.window_max`
  are accepted as direct-Rust native candidates.
- The wheel in `dist/` carries a platform tag (e.g. `cp313-...`) because it
  contains the `_rextio_native` extension; if the native build fails,
  packaging still produces a pure-Python `py3-none-any` wheel that works
  through the fallback.
- The installed package tries native first: set `REXTIO_NATIVE_MODE=fallback`
  before running to force the Python fallback and compare behavior (results
  are identical - that is the contract).

Compare performance:

```text
rextio bench wheel_package.series.harmonic_like --project-root examples/wheel_package
```

Numbers depend on the machine; treat them as smoke demonstrations.
