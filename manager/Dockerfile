# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

# Install wget and tar to fetch the ONNX Runtime shared library.
RUN apk add --no-cache wget tar

WORKDIR /app

# Download ONNX Runtime shared library for Linux/amd64.
# The version here must match the API version constant in internal/ai/predictor.go (23 → ORT 1.23.x).
ARG ORT_VERSION=1.23.0
RUN wget -q "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/onnxruntime-linux-x64-${ORT_VERSION}.tgz" \
    && tar -xzf "onnxruntime-linux-x64-${ORT_VERSION}.tgz" \
    && cp "onnxruntime-linux-x64-${ORT_VERSION}/lib/libonnxruntime.so.${ORT_VERSION}" /usr/local/lib/libonnxruntime.so \
    && rm -rf "onnxruntime-linux-x64-${ORT_VERSION}" "onnxruntime-linux-x64-${ORT_VERSION}.tgz"

# Resolve dependencies before copying source for better layer caching.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build — CGO_ENABLED=0 because onnxruntime-purego loads the .so via purego
# (no CGo required). The binary is statically linked apart from the ONNX Runtime .so.
RUN CGO_ENABLED=0 GOOS=linux go build -o snffr-manager ./main.go

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime
# ─────────────────────────────────────────────────────────────────────────────
FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /root/

# Copy the binary.
COPY --from=builder /app/snffr-manager .

# Copy the ONNX Runtime shared library.
COPY --from=builder /usr/local/lib/libonnxruntime.so /usr/local/lib/libonnxruntime.so

# Copy the ONNX model.
COPY --from=builder /app/models/ids_model.onnx ./models/ids_model.onnx

# Copy the rules file.
COPY --from=builder /app/rules.yaml ./rules.yaml

# Make the ONNX Runtime .so discoverable at runtime.
ENV LD_LIBRARY_PATH=/usr/local/lib

EXPOSE 50051

CMD ["./snffr-manager"]
