FROM golang:1.23.3-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN mkdir -p /app/auth/templates
COPY auth/templates/*.html /app/auth/templates/

RUN cd auth && go build -o main

EXPOSE 80

WORKDIR /app/auth

CMD ["./main"]