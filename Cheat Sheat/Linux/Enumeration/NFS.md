### NFS-Common

Description: A package that includes useful programs for NFS

List NFS shares: `/usr/sbin/showmount -e [IP]`

#### Mount a share

1. Make a directory to mount the share to: `mkdir /tmp/mount`
2. Mount the share `sudo mount -t nfs [ip address]:[share] /tmp/mount/ -nolock`