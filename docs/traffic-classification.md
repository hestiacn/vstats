# Optional traffic classification

The native fix recognizes a bounded `Bytespider` marker before the mobile/tablet
robot exemption, preserving the `Bytespider/` history ID and display entry.
It also precedes other robots.pm rules (e.g. generic `spider`), so matching desktop/TV/wearable requests move to `Bytespider/`; other device detection, rules and accounting stay unchanged.
Other robots.pm markers inside mobile or tablet user agents remain subject to the existing exemption; this fix does not change them.
Owners of customized `robots.pm` files must merge its new `BytespiderRobotID`
helper too; without it the parser retains its previous behavior.
