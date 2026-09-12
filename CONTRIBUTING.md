# Contributing

Use Go 1.26+ and Node 24 for development. The frontend is intentionally small and dependency-free at runtime. Keep UI assets local and keep network queries out of frontend code except same-origin API calls.

Before submitting a change:

```bash
gofmt -w *.go
go mod tidy
go vet ./...
go test -race ./...
npm test
npm run test:browser
```

DNS changes need tests against local fake upstreams, including UDP and TCP behavior. Do not make automated tests depend on public DNS responses. Configuration changes need validation, persistence-failure handling and concurrency review. UI changes should work on mobile, retain keyboard access and show honest empty/error states.

Do not commit `.env`, runtime data, personal query history, credentials, or real household client identifiers. Browser fixtures use illustrative domains and addresses and are labelled as previews. Keep the validation document accurate; distinguish checks actually executed from checks merely added to CI.
