FROM golang:1.24 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /reveald ./cmd/reveald/

FROM gcr.io/distroless/static-debian12
COPY --from=builder /reveald /reveald
ENTRYPOINT ["/reveald"]
