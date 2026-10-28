# Ideas

1. Add an opt-in compile flag to bundle proving keys into the generated WASM
   module. Applications could prove without separately fetching or supplying
   key files. Keep external key loading as the default, since bundled keys
   increase the WASM download size and require rebuilding it when keys change.
