# Variables
IMAGE := tls-scanner
CONTAINER := tls-scanner-container

# Build the Docker image
build:
	docker build -t $(IMAGE) .

# Run the container
run:
	docker run --rm --name $(CONTAINER) $(IMAGE)

# Rebuild without cache
rebuild:
	docker build --no-cache -t $(IMAGE) .

# Open a shell inside container (for debugging)
shell:
	docker run --rm -it --name $(CONTAINER) $(IMAGE) bash

# Stop the running container
stop:
	docker stop $(CONTAINER) || true
