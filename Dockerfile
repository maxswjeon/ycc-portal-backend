FROM golang:1.19-alpine as builder

RUN apk add --no-cache --virtual .build-deps bash gcc git musl-dev ca-certificates
RUN mkdir /app
WORKDIR /app
COPY . /app
RUN go get
RUN CGO_ENABLED=0 GOOS=linux go build -tags=nomsgpack -installsuffix cgo -ldflags '-extldflags "-static"' -a -o main .



FROM scratch

# Must copy the CA certs!
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY ./templates /templates
COPY --from=builder /app/main /main
COPY --from=builder /usr/local/go/lib/time/zoneinfo.zip /usr/local/go/lib/time/zoneinfo.zip
ENV ZONEINFO=/zoneinfo.zip 

ENTRYPOINT ["/main"]
