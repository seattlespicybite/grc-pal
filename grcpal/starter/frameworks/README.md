# Frameworks

Each YAML file here adds a framework GRC-pal can map controls to and report coverage for.

```yaml
id: nist-csf-2          # short ID used in control mappings
name: NIST CSF 2.0
version: "2.0"
description: One line
requirements:
  - {id: GV.OC-01, title: "Organizational mission is understood", group: "Govern"}
```

Map a control in `catalog/controls.yaml` with `mappings: {nist-csf-2: [GV.OC-01]}`. SOC 2 uses the
`criteria` field and ISO 27001 the `iso27001` field for historical reasons; both also accept
`mappings`. Frameworks can also be created in the portal (Frameworks > New framework).
