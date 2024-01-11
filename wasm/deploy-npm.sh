# build web
wasm-pack build --target web
cp pkg/nomic_wasm.js pkg/nomic_wasm.d.ts pkg/nomic_wasm_bg.wasm npm

# build nodejs
wasm-pack build --target nodejs
cp pkg/nomic_wasm.js npm/nomic_wasm_main.js 
cp pkg/nomic_wasm_bg.wasm npm/nomic_wasm_bg_main.wasm 
sed -i '' 's|nomic_wasm_bg.wasm|nomic_wasm_bg_main.wasm|g' npm/nomic_wasm_main.js

# deploy npm
cd npm 
yarn publish --access public --patch
