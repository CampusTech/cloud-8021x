FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /acme-authz-webhook .

FROM gcr.io/distroless/static-debian12
COPY --from=build /acme-authz-webhook /acme-authz-webhook
ENTRYPOINT ["/acme-authz-webhook", "serve"]
