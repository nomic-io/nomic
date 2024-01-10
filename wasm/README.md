## How to build wasm module

1. Build for web `RUSTFLAGS: '-C link-arg=-s' wasm-pack build --target web` then `cp pkg/nomic_wasm.js pkg/nomic_wasm.d.ts pkg/nomic_wasm_bg.wasm npm`
1. Build for nodejs `RUSTFLAGS: '-C link-arg=-s' wasm-pack --target nodejs` then `cp pkg/nomic_wasm.js npm/nomic_wasm_main.js && cp pkg/nomic_wasm_bg.wasm npm/nomic_wasm_bg_main.wasm`
1. Deploy new package `cd npm yarn publish --access public --patch`
