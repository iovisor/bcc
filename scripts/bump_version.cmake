# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

configure_file(SPECS/Dockerfile.el6.in SPECS/Dockerfile.el6 @ONLY)
configure_file(SPECS/Dockerfile.el7.in SPECS/Dockerfile.el7 @ONLY)
configure_file(SPECS/Dockerfile.f22.in SPECS/Dockerfile.f22 @ONLY)
configure_file(SPECS/bcc.el6.spec.in SPECS/bcc.el6.spec @ONLY)
configure_file(SPECS/bcc.el7.spec.in SPECS/bcc.el7.spec @ONLY)
configure_file(SPECS/bcc.f22.spec.in SPECS/bcc.f22.spec @ONLY)
configure_file(scripts/build-deb.sh.in scripts/build-deb.sh @ONLY)
