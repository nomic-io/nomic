## How to build wasm module

1. Build for web `wasm-pack build --target web` then `cp pkg/nomic_wasm.js pkg/nomic_wasm.d.ts pkg/nomic_wasm_bg.wasm npm`
1. Build for nodejs `wasm-pack build --target nodejs` then `cp pkg/nomic_wasm.js npm/nomic_wasm_main.js && cp pkg/nomic_wasm_bg.wasm npm/nomic_wasm_bg_main.wasm && sed -i '' 's|nomic_wasm_bg.wasm|nomic_wasm_bg_main.wasm|g' npm/nomic_wasm_main.js`
1. Deploy new package `cd npm && yarn publish --access public --patch`
