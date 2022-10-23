.PHONY: standalone
standalone:
	cd dockerfile
	docker build -t bc5gc/ueran:0.1.0 ./dockerfile/ueransim
	docker build -t bc5gc/cncpp:0.1.0 ./dockerfile/cncpp-5gaka
	docker pull nginx:latest
	docker network create ethtest_privnet --subnet=11.11.11.0/24