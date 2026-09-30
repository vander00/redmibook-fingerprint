.PHONY: srpm

srpm:
	dnf -y install git rpm-build tar gzip
	@set -eu; \
	git submodule update --init --recursive -- asyncdbus asyncusb jinx; \
	name=$$(rpmspec -q --srpm --qf '%{NAME}' "$(spec)"); \
	version=$$(rpmspec -q --srpm --qf '%{VERSION}' "$(spec)"); \
	workdir=$$(mktemp -d); \
	trap 'rm -rf "$$workdir"' EXIT; \
	mkdir -p "$$workdir/$$name-$$version" "$$workdir/rpmbuild" "$(outdir)"; \
	git archive HEAD | tar -x -C "$$workdir/$$name-$$version"; \
	for module in asyncdbus asyncusb jinx; do \
	    mkdir -p "$$workdir/$$name-$$version/$$module"; \
	    git -C "$$module" archive HEAD | tar -x -C "$$workdir/$$name-$$version/$$module"; \
	done; \
	tar -C "$$workdir" -czf "$$workdir/$$name-$$version.tar.gz" "$$name-$$version"; \
	rpmbuild -bs \
	    --define "_topdir $$workdir/rpmbuild" \
	    --define "_sourcedir $$workdir" \
	    --define "_srcrpmdir $(outdir)" \
	    "$(spec)"