all: clean
	@ echo "    * Building listener_beacon_udp plugin"
	@ mkdir dist
	@ cp config.json ax_config.axs ./dist/
	@ GOEXPERIMENT=jsonv2,greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/listener_beacon_udp.so pl_main.go pl_udp.go pl_listener.go
	@ echo "      done..."

clean:
	@ rm -rf dist
