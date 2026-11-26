SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := check
TOOLING := uv run --locked --project tooling
TOOLING_IMAGE := ghcr.io/neurwerk/k8s-stack-addon-dependency-track-tooling
BASE_REPO ?=

.PHONY: tooling-check tooling-build check
tooling-check:
	uv lock --check --project tooling
	$(TOOLING) ruff check tooling
	$(TOOLING) ruff format --check tooling
	$(TOOLING) ty check --project tooling
	sh -n tooling/src/dependency_track_tooling/payloads/scan-images.sh
	node --check tooling/src/dependency_track_tooling/payloads/scan-repositories.mjs

tooling-build:
	@test -n "$(VERSION)" -a -n "$(REVISION)" || { echo 'Set VERSION and REVISION'; exit 1; }
	docker build --build-arg VERSION="$(VERSION)" --build-arg REVISION="$(REVISION)" -t "$(TOOLING_IMAGE):$(VERSION)" tooling

check: tooling-check
	@test -n "$(BASE_REPO)" || { echo 'Set BASE_REPO to the selected Base checkout'; exit 1; }
	$(TOOLING) addon-check "$(CURDIR)" --base "$(BASE_REPO)"
	helm lint --strict charts/dependency-track --set dependencyTrack.enabled=true --set dependencyTrack.collection.enabled=true
	helm template check charts/dependency-track --set dependencyTrack.enabled=true --set dependencyTrack.collection.enabled=true --set dependencyTrack.collection.discoverRunningImages=true --set 'dependencyTrack.collection.kubernetesApiCidrs[0]=192.0.2.10/32' | kubeconform -strict -summary -ignore-missing-schemas
	helm lint --strict charts/dependency-track/routing --set dependencyTrack.enabled=true --set dependencyTrack.hostname=dependencies.example.com --set externalGateway.enabled=true
	helm template check charts/dependency-track/routing --set dependencyTrack.enabled=true --set dependencyTrack.hostname=dependencies.example.com --set externalGateway.enabled=true | kubeconform -strict -summary -ignore-missing-schemas
	@for dir in releases/namespaces/dependency-track releases/dependency-track/*; do \
		kustomize build "$$dir" | kubeconform -strict -summary -ignore-missing-schemas; \
	done
