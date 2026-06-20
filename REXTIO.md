# Rextio Public 1 Notes

Rextio Public 1 proves a focused hybrid build workflow:

```text
Python source
  -> Rextio analyzer
  -> compatible subset checker
  -> boundary safety checker
  -> generated native artifact and Python fallback
```

Native compilation is an optimization. Fallback Python behavior must remain
available, including when `REXTIO_DISABLE_NATIVE=1` is set.
