# Trusted side: LLM credential gateway (-mode llm) and relay (-mode relay).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod *.go routes.json ./
RUN go vet ./... && go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/re-gateway .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/re-gateway /re-gateway
USER 10001:10001
ENTRYPOINT ["/re-gateway"]
