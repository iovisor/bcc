build_centos7_rpms:
	docker build -t bcc:centos -f SPECS/Dockerfile.centos7 .

build_centos7: build_centos7_rpms
	$(eval CONTAINER := $(shell docker create bcc:centos --name bcc_centos))
	docker cp $(CONTAINER):/rpms . && \
	docker rm $(CONTAINER)
