# syntax=docker/dockerfile:1

# --- Build stage ---
FROM golang:alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /bin/controlplane ./cmd/controlplane

# --- Runtime stage ---
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /bin/controlplane /usr/local/bin/controlplane

EXPOSE 8080
ENTRYPOINT ["controlplane"]
