---
backups:
  append:
  - .bak
  - '~'
  - .old
  - .orig
  - .save
  rename:
  - .bak
  - .zip
  - .tar.gz
  swap:
  - .{file}.swp
  - .{file}.swo
---

# Backup Name Templates

Name templates the planner hands the backup scan, so an editor or archive twin of an observed file is probed for the `sensitive-file-exposure` finding. The capability reads no knowledge, it acts on the templates it is given.
