.ONESHELL:
PRODUCT_NAME=pathology-core
BASENAME=$(PRODUCT_NAME)
BINDIR=bin
LIBNAME=$(PRODUCT_NAME)
CLINAME=PathologyCli

BRANCH=$(shell git branch --show-current)
VERSION=$(shell git describe --tags || echo "unknown version")
# Windows CI uses MinGW make; do not put bare text inside ifeq (missing separator).
CRONET_GO_VERSION := $(shell cat ../vendor/sing-box-lx/.github/CRONET_GO_VERSION)
# Single source of truth: build_tags.txt (see that file for lx / Hiddify rationale).
# Escape \# so Make does not treat it as a comment inside $(shell ...) (BSD/GNU).
TAGS=$(shell grep -v '^[[:space:]]*\#' build_tags.txt | grep -v '^[[:space:]]*$$' | tr -d '\r' | head -n1)
IOS_ADD_TAGS=with_low_memory,with_purego
MACOS_ADD_TAGS=
WINDOWS_ADD_TAGS=with_purego
LDFLAGS=-w -s -checklinkname=0 -buildid= $${CODE_VERSION}
GOBUILDLIB=CGO_ENABLED=1 go build -trimpath -ldflags="$(LDFLAGS)" -buildmode=c-shared
GOBUILDSRV=CGO_ENABLED=1 go build -ldflags="$(LDFLAGS)" -trimpath -tags $(TAGS)

CRONET_DIR=./cronet
.PHONY: protos
protos:
	go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest
	# protoc --go_out=./ --go-grpc_out=./ --proto_path=hiddifyrpc hiddifyrpc/*.proto
	# for f in $(shell find v2 -name "*.proto"); do \
	# 	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $$f; \
	# done
	# for f in $(shell find extension -name "*.proto"); do \
	# 	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $$f; \
	# done
	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	protoc --doc_out=./docs  --doc_opt=markdown,hiddifyrpc.md $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	# protoc --js_out=import_style=commonjs,binary:./extension/html/rpc/ --grpc-web_out=import_style=commonjs,mode=grpcwebtext:./extension/html/rpc/ $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	# npx browserify extension/html/rpc/extension.js >extension/html/rpc.js


lib_install: prepare
	go install -v github.com/sagernet/gomobile/cmd/gomobile@v0.1.11
	go install -v github.com/sagernet/gomobile/cmd/gobind@v0.1.11
	# Optional: webui/extension protobuf tooling. Android CI sets SKIP_CORE_NPM=1.
	if [ "$${SKIP_CORE_NPM}" != "1" ]; then npm install; fi

headers:
	go build -buildmode=c-archive -o $(BINDIR)/ ./platform/desktop2

android: lib_install
	# Do not pass -gcflags "all=-N -l" here: disables opts and makes CI gomobile hang for hours.
	CGO_LDFLAGS="-O2 -g -s -w -Wl,-z,max-page-size=16384" gomobile bind -androidapi=21 -javapkg=com.pathology.core -libname=pathology-core -tags=$(TAGS) -trimpath -ldflags="$(LDFLAGS)" -target=android -o $(BINDIR)/$(LIBNAME).aar github.com/sagernet/sing-box/experimental/libbox ./platform/mobile

ios-full: lib_install
	gomobile bind -v  -target ios,iossimulator,tvos,tvossimulator,macos -libname=pathology-core -tags=$(TAGS),$(IOS_ADD_TAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(BINDIR)/$(PRODUCT_NAME).xcframework github.com/sagernet/sing-box/experimental/libbox ./platform/mobile 
	mv $(BINDIR)/$(PRODUCT_NAME).xcframework $(BINDIR)/$(LIBNAME).xcframework 
	cp PathologyCore.podspec $(BINDIR)/$(LIBNAME).xcframework/

ios: lib_install
	gomobile bind -v  -target ios -libname=pathology-core -tags=$(TAGS),$(IOS_ADD_TAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(BINDIR)/PathologyCore.xcframework github.com/sagernet/sing-box/experimental/libbox ./platform/mobile
	cp Info.plist $(BINDIR)/PathologyCore.xcframework/


webui:
	curl -L -o webui.zip  https://github.com/hiddify/Yacd-meta/archive/gh-pages.zip 
	unzip -d ./ -q webui.zip
	rm webui.zip
	rm -rf bin/webui
	mv Yacd-meta-gh-pages bin/webui

.PHONY: build
windows-amd64: prepare
	set -e
	rm -rf $(BINDIR)/*
	mkdir -p $(BINDIR)
	# Prefer go.mod-pinned lib module (sum-verified). build-naive extract-lib was
	# removed upstream and left CI without libcronet.dll → Flutter cmake install fails.
	go mod download github.com/sagernet/cronet-go/lib/windows_amd64
	CRONET_DIR=$$(go list -m -f '{{.Dir}}' github.com/sagernet/cronet-go/lib/windows_amd64)
	test -n "$$CRONET_DIR"
	test -f "$$CRONET_DIR/libcronet.dll"
	cp "$$CRONET_DIR/libcronet.dll" $(BINDIR)/libcronet.dll
	env GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc  $(GOBUILDLIB) -tags $(TAGS),$(WINDOWS_ADD_TAGS)   -o $(BINDIR)/$(LIBNAME).dll ./platform/desktop
	echo "core built, now building cli" 
	ls -R $(BINDIR)/
	go install -mod=readonly github.com/akavel/rsrc@latest
	cp $(BINDIR)/$(LIBNAME).dll ./$(LIBNAME).dll
	$$(go env GOPATH)/bin/rsrc -ico ./assets/pathology-cli.ico -o ./cmd/bydll/cli.syso
	env GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CGO_LDFLAGS="$(LIBNAME).dll" $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME).exe ./cmd/bydll
	rm -f ./*.dll
	test -f $(BINDIR)/$(LIBNAME).dll
	test -f $(BINDIR)/$(CLINAME).exe
	test -f $(BINDIR)/libcronet.dll

# 	make webui
	



cronet-%:
	$(MAKE) ARCH=$* build-cronet

build-cronet:
# 	rm -rf $(CRONET_DIR)
	git init $(CRONET_DIR) || echo "dir exist"
	cd $(CRONET_DIR) && \
	git remote add origin https://github.com/sagernet/cronet-go.git ||echo "remote exist"; \
	git fetch --depth=1 origin $(CRONET_GO_VERSION) && \
	git checkout FETCH_HEAD && \
	git submodule update --init --recursive --depth=1 && \
	if [ "$${VARIANT}" = "musl" ]; then \
		go run ./cmd/build-naive --target=linux/$(ARCH) --libc=musl download-toolchain && \
		go run ./cmd/build-naive --target=linux/$(ARCH) --libc=musl env > cronet.env; \
	else \
		go run ./cmd/build-naive --target=linux/$(ARCH) download-toolchain && \
		go run ./cmd/build-naive --target=linux/$(ARCH) env > cronet.env; \
	fi

################################
# Generic Linux Builder
################################
linux-%:
	$(MAKE) ARCH=$* build-linux

define load_cronet_env
set -a; \
while IFS= read -r line; do \
    key=$${line%%=*}; \
    value=$${line#*=}; \
    export "$$key=$$value"; \
	echo "$$key=$$value"; \
done < $(CRONET_DIR)/cronet.env; \
set +a;
endef

build-linux: prepare
	mkdir -p $(BINDIR)/lib

	$(load_cronet_env)
	FINAL_TAGS=$(TAGS); \
	if [ "$${VARIANT}" = "musl" ]; then \
		FINAL_TAGS=$${FINAL_TAGS},with_musl; \
	elif [ "$${VARIANT}" = "purego" ]; then \
		FINAL_TAGS="$${FINAL_TAGS},with_purego"; \
	fi; \
	echo "FinalTags: $$FINAL_TAGS"; \
	GOOS=linux GOARCH=$(ARCH) $(GOBUILDLIB) -tags $${FINAL_TAGS} -o $(BINDIR)/lib/$(LIBNAME).so ./platform/desktop ;\
	
	echo "Core library built, now building CLI with CGO linking to core library"
	mkdir lib
	cp $(BINDIR)/lib/$(LIBNAME).so ./lib/$(LIBNAME).so

	GOOS=linux GOARCH=$(ARCH) CGO_LDFLAGS="./lib/$(LIBNAME).so -Wl,-rpath,\$$ORIGIN/lib -fuse-ld=lld" $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME) ./cmd/bydll
	
	rm -rf ./lib/*.so
	chmod +x $(BINDIR)/$(CLINAME)
	if [ ! -f $(BINDIR)/lib/$(LIBNAME).so -o ! -f $(BINDIR)/$(CLINAME) ]; then \
		echo "Error: $(LIBNAME).so or $(CLINAME) not built"; \
		ls -R $(BINDIR); \
		exit 1; \
	fi
# 	make webui


linux-custom: prepare  install_cronet
	mkdir -p $(BINDIR)/
	#env GOARCH=mips $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME) ./cmd/
	$(load_cronet_env)
	go build -ldflags="$(LDFLAGS)" -trimpath -tags $(TAGS) -o $(BINDIR)/$(CLINAME) ./cmd/main
	chmod +x $(BINDIR)/$(CLINAME)
	make webui

macos-amd64:
	env GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-mmacosx-version-min=10.15 -O2" CGO_LDFLAGS="-mmacosx-version-min=10.15 -O2 -lpthread" CGO_ENABLED=1 go build -trimpath -ldflags="$(LDFLAGS)" -tags $(TAGS),$(MACOS_ADD_TAGS) -buildmode=c-shared -o $(BINDIR)/$(LIBNAME)-amd64.dylib ./platform/desktop
macos-arm64:
	env GOOS=darwin GOARCH=arm64 CGO_CFLAGS="-mmacosx-version-min=10.15 -O2" CGO_LDFLAGS="-mmacosx-version-min=10.15 -O2 -lpthread" CGO_ENABLED=1 go build -trimpath -ldflags="$(LDFLAGS)" -tags $(TAGS),$(MACOS_ADD_TAGS) -buildmode=c-shared -o $(BINDIR)/$(LIBNAME)-arm64.dylib ./platform/desktop
	
macos: prepare macos-amd64 macos-arm64 
	
	lipo -create $(BINDIR)/$(LIBNAME)-amd64.dylib $(BINDIR)/$(LIBNAME)-arm64.dylib -output $(BINDIR)/$(LIBNAME).dylib
	cp $(BINDIR)/$(LIBNAME).dylib ./$(LIBNAME).dylib 
	mv $(BINDIR)/$(LIBNAME)-arm64.h $(BINDIR)/desktop.h 
	# env GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-mmacosx-version-min=10.15" CGO_LDFLAGS="-mmacosx-version-min=10.15" CGO_LDFLAGS="bin/$(LIBNAME).dylib"  CGO_ENABLED=1 $(GOBUILDSRV)  -o $(BINDIR)/$(CLINAME) ./cmd/bydll
	# rm ./$(LIBNAME).dylib
	# chmod +x $(BINDIR)/$(CLINAME)

prepare: 
	go mod tidy

clean:
	rm $(BINDIR)/*




.PHONY: release
release: # Create a new tag for release.	
	@bash -c '.github/change_version.sh'
	


