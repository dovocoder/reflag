# --- Stage 1: Build frontend ---
FROM node:22-alpine AS frontend-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ ./
RUN npx tsc -b && npx vite build

# --- Stage 2: Build Go binary ---
FROM golang:1.26-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend-builder /app/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o reflag .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o reflag-run ./cmd/reflag-run/

# --- Stage 3: Runtime ---
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -S app && adduser -S -G app -h /app app

WORKDIR /app
COPY --from=go-builder /app/reflag /app/reflag
COPY --from=go-builder /app/reflag-run /app/reflag-run

RUN mkdir -p /app/data && chown -R app:app /app
USER app

ENV PORT=8080
ENV DB_PATH=/app/data/reflag.db
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/reflag"]
