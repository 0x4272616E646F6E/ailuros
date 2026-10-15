
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 \
  GOOS=$TARGETOS \
  GOARCH=$TARGETARCH \
  go build -trimpath -ldflags="-s -w -X github.com/0x4272616E646F6E/ailuros/internal/version.Version=${VERSION}" \
  -o /out/ailuros ./cmd/ailuros

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/ailuros /ailuros
EXPOSE 9001 9002 9003 9090
ENTRYPOINT ["/ailuros"]
