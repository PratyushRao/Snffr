FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o snffr-manager ./main.go

# Runtime
FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /root/

# Copy the binary
COPY --from=builder /app/snffr-manager .

EXPOSE 50051

# Run
CMD ["./snffr-manager"]
