msbuild Aurora\Aurora.slnx /p:Configuration=Release
go generate
go build -ldflags="-H windowsgui"