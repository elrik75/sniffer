export PATH=$PATH:/usr/local/go/bin/
export GOPATH=$PWD
export GOMAXPROCS=8
alias bb="go build -o sniffer main.go"

function fmt {
         gofmt --tabs=false --tabwidth=4 $1 >/tmp/gofmt
         mv /tmp/gofmt "$1"
}
