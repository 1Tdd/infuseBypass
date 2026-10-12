#!/bin/bash
set -euo pipefail
mkdir -p build/tools
xcodebuild -version
xcodebuild -project InfuseBypass.xcodeproj -target InfuseBypass \
  -configuration Release -sdk appletvos \
  ARCHS=arm64 ONLY_ACTIVE_ARCH=NO TVOS_DEPLOYMENT_TARGET=13.0 \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
  DEVELOPMENT_TEAM="" ENABLE_MODULE_VERIFIER=NO \
  SYMROOT="$PWD/build/products" OBJROOT="$PWD/build/intermediates" build

# Compile upstream's insertion tool from an immutable, reviewed commit.
git init build/insert_dylib
git -C build/insert_dylib remote add origin https://github.com/tyilo/insert_dylib.git
git -C build/insert_dylib fetch --depth 1 origin eb7278162af8fcc372e7f2946a2dee6a386b17d8
git -C build/insert_dylib checkout --detach FETCH_HEAD
test "$(git -C build/insert_dylib rev-parse HEAD)" = eb7278162af8fcc372e7f2946a2dee6a386b17d8
xcrun --sdk macosx clang -O2 build/insert_dylib/insert_dylib/main.c -o build/tools/insert_dylib
test -f build/products/Release-appletvos/InfuseBypass.framework/InfuseBypass
