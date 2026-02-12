# opencloudmesh-go

Open Cloud Mesh (OCM) reference implementation in Go. Delivered as the M5 (OCM Stub Implementation) milestone of the [Sovereign Tech Fund](https://github.com/orgs/cs3org/projects/3/views/1) funded OCM project.

## Purpose

This project provides an OCM-compliant server stub: capability discovery, loading certificates, ACME auto TLS, configurability, Docker deployment, and full support in the OCM Test Suite. It is the reference implementation of the OCM protocol.

## OCM-STA and Milestones

Project tasks and milestones are coordinated in the [OCM-STA repository](https://github.com/cs3org/OCM-STA). OCM-STA holds Sovereign Tech Fund activity tracking. M5 (OCM Stub Implementation) is delivered by this repo.

## Build and test

```sh
# Build
make build

# Unit and integration tests (excludes E2E)
make test

# E2E tests (requires make test-e2e-install once)
make test-e2e
```

## OCM-API specification

Protocol behavior is defined in the [OCM-API IETF-RFC](https://github.com/cs3org/OCM-API/blob/615192eeff00bcd479364dfa9c1f91641ac7b505/IETF-RFC.md?plain=1#ocm-api-discovery).
