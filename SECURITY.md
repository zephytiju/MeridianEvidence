<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security policy

Do not report suspected vulnerabilities in public issues. Use GitHub's private vulnerability
reporting for `zephytiju/meridian-storage-evidence`.

Evidence records and public errors must not carry secrets, credentials, unrestricted request or
response bodies, provider endpoints, or physical storage names. Applications authorize Evidence
reads before constructing Operations. Adapters and deployment systems remain responsible for
storage access controls, encryption, retention execution, recovery, and lifecycle.

Only the latest 1.x release receives security fixes until another support policy is published.
