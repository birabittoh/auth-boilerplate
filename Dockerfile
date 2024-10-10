# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS builder

WORKDIR /build

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify

# Transfer source code
COPY src ./src
COPY *.go ./

# Build
RUN CGO_ENABLED=0 go build -trimpath -o /dist/app


# Test
FROM builder AS run-test-stage
COPY templates ./templates
RUN go test -v ./...

FROM scratch AS build-release-stage

WORKDIR /app

COPY static ./static
COPY templates ./templates
COPY --from=builder /dist .

ENTRYPOINT ["./app"]
