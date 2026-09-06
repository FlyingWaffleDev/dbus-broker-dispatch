| Capability           | broker-launch |           dispatch |
| -------------------- | ------------: | -----------------: |
| D-Bus XML policy     |             ✓ |                  ✓ |
| `Exec=` activation   |             ✓ |                  ✓ |
| `SystemdService=`    |             ✓ | Exec fallback only |
| config reload        |             ✓ |                  ✓ |
| user bus             |             ✓ |                  ✓ |
| system bus           |             ✓ |                  ✓ |
| AppArmor             |             ✓ |                  ✓ |
| SELinux associations |             ✓ |                  ✓ |
| systemd dependency   |           yes |                 no |
| OpenRC               |             — |             tested |
| runit                |             — |          simulated |
| s6                   |             — |          simulated |
| dinit                |             — |          simulated |
