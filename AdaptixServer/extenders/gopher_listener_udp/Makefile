all: clean
	@ echo "    * Building listener_gopher_quic plugin"
	@ mkdir dist
	@ cp config.json ax_config.axs ./dist/
	@ GOEXPERIMENT=jsonv2,greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/listener_gopher_quic.so pl_main.go pl_listener.go pl_quic.go map.go
	@ echo "      done..."

clean:
	@ rm -rf dist
