POLICY_NAME = tls_probe

all: $(POLICY_NAME).pp

$(POLICY_NAME).pp: $(POLICY_NAME).te $(POLICY_NAME).fc $(POLICY_NAME).if
	make -f /usr/share/selinux/devel/Makefile $(POLICY_NAME).pp

install: $(POLICY_NAME).pp
	sudo semodule -i $(POLICY_NAME).pp
	sudo restorecon -R /usr/local/bin/tls-probe /var/log/tls-probe 2>/dev/null || true

uninstall:
	sudo semodule -r $(POLICY_NAME) || true

clean:
	rm -f $(POLICY_NAME).pp *.mod *.mod.fc tmp/

.PHONY: all install uninstall clean
