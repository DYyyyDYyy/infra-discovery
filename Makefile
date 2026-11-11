NET      := idlab
SUBNET   := 172.30.250.0/24
HOSTS    := web db cache app
IP_web   := 172.30.250.11
IP_db    := 172.30.250.12
IP_cache := 172.30.250.13
IP_app   := 172.30.250.14
TARGETS  := $(foreach h,$(HOSTS),$(IP_$(h)))
KEY      := lab/id_ed25519
DB       ?= cmdb.sqlite
DISCOVER := uv run discover --db $(DB)

.PHONY: lab lab-down scan scan-check serve test lint fmt clean

$(KEY):
	ssh-keygen -q -t ed25519 -N "" -C infra-discovery-lab -f $(KEY)

lab: $(KEY)
	docker network inspect $(NET) >/dev/null 2>&1 || docker network create --subnet $(SUBNET) $(NET)
	@for h in $(HOSTS); do docker build -q -t idlab-$$h -f lab/$$h.Dockerfile lab || exit 1; done
	@for h in $(HOSTS); do docker rm -f idlab-$$h >/dev/null 2>&1; done
	docker run -d --name idlab-web   --hostname web   --network $(NET) --network-alias web   --ip $(IP_web)   idlab-web
	docker run -d --name idlab-db    --hostname db    --network $(NET) --network-alias db    --ip $(IP_db)    idlab-db
	docker run -d --name idlab-cache --hostname cache --network $(NET) --network-alias cache --ip $(IP_cache) idlab-cache
	docker run -d --name idlab-app   --hostname app   --network $(NET) --network-alias app   --ip $(IP_app)   idlab-app
	uv run discover wait $(TARGETS) --settle 5

lab-down:
	@for h in $(HOSTS); do docker rm -f idlab-$$h >/dev/null 2>&1; done
	-docker network rm $(NET)

scan:
	$(DISCOVER) scan $(TARGETS) --key $(KEY)

# a second scan of an unchanged lab must produce an empty diff
scan-check:
	$(DISCOVER) scan $(TARGETS) --key $(KEY) --expect-no-changes

serve:
	$(DISCOVER) serve

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

fmt:
	uv run ruff format .
	uv run ruff check --fix .

clean:
	rm -f $(DB)
