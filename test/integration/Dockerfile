FROM golang:1.27@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY test/integration/stubmodel test/integration/stubmodel
COPY test/integration/echo test/integration/echo
RUN CGO_ENABLED=0 go build -tags integration -trimpath -o /out/stubmodel ./test/integration/stubmodel \
 && CGO_ENABLED=0 go build -tags integration -trimpath -o /out/echo ./test/integration/echo

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS stubmodel
COPY --from=build /out/stubmodel /stubmodel
EXPOSE 8080
ENTRYPOINT ["/stubmodel"]

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS echo
COPY --from=build /out/echo /echo
EXPOSE 8080 8081
ENTRYPOINT ["/echo"]
