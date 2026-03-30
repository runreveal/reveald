FROM --platform=$BUILDPLATFORM golang:1.24 AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /reveald ./cmd/reveald/

FROM gcr.io/distroless/static-debian12
COPY --from=builder /reveald /reveald
ENTRYPOINT ["/reveald"]
