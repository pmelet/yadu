package main

import (
	"flag"
	"fmt"
	"github.com/docker/go-units"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"log"
	"os"
	"path"
)

type content struct {
	size int64
	name string
	sub  map[string]*content
}

func readDir(filename string) (*content, error) {
	fileInfo, err := os.Lstat(filename)
	if err != nil {
		if !*FLAG_quiet {
			log.Print(err)
		}
		return nil, err
	}
	if !fileInfo.IsDir() {
		return &content{size: fileInfo.Size(), name: path.Base(filename)}, nil
	}
	ms, err := MountPointStatus(filename)
	if err != nil {
		if !*FLAG_quiet {
			log.Print(err)
		}
		return nil, err
	}
	//log.Printf("%s: %s\n", filename, FileSystems[ms.Type])
	if ExcludeTypes[ms.Type] {
		log.Printf("Exclude %s (filesystem is %s)\n", filename, FileSystems[ms.Type])
		return nil, nil
	}
	ret := content{name: path.Base(filename), sub: make(map[string]*content), size: fileInfo.Size()}
	files, err := ioutil.ReadDir(filename)
	if err != nil {
		if !*FLAG_quiet {
			log.Print(err)
		}
		return nil, err
	}
	for _, f := range files {
		c, err := readDir(path.Join(filename, f.Name()))
		if err == nil && c != nil {
			ret.sub[f.Name()] = c
			ret.size += c.size
		}
	}
	return &ret, nil
}

func (c content) displayMap(indent string, minsize int64, show_small_leaf bool) {
	expand := c.size > minsize
	mark := "+"
	if expand {
		mark = "-"
	}
	if expand || show_small_leaf {
		fmt.Printf("%s(%s)%s: %s\n", indent, mark, c.name, displaySize(c.size))
	}
	if expand {
		for _, v := range c.sub {
			v.displayMap(indent+"  ", minsize, show_small_leaf)
		}
	}
}

func displaySize(size int64) string {
	if *FLAG_human {
		return units.HumanSize(float64(size))
	} else if *FLAG_giga {
		return fmt.Sprintf("%.4gGiB", float64(size)/units.GiB)
	} else if *FLAG_mega {
		return fmt.Sprintf("%.4gMiB", float64(size)/units.MiB)
	}
	return fmt.Sprintf("%d", size)
}

const (
	ADFS_SUPER_MAGIC      = 0xadf5
	AFFS_SUPER_MAGIC      = 0xadff
	AFS_SUPER_MAGIC       = 0x5346414f
	ANON_INODE_FS_MAGIC   = 0x09041934
	AUTOFS_SUPER_MAGIC    = 0x0187
	BDEVFS_MAGIC          = 0x62646576
	BEFS_SUPER_MAGIC      = 0x42465331
	BFS_MAGIC             = 0x1badface
	BINFMTFS_MAGIC        = 0x42494e4d
	BPF_FS_MAGIC          = 0xcafe4a11
	BTRFS_SUPER_MAGIC     = 0x9123683e
	BTRFS_TEST_MAGIC      = 0x73727279
	CGROUP_SUPER_MAGIC    = 0x27e0eb   /* Cgroup pseudo FS */
	CGROUP2_SUPER_MAGIC   = 0x63677270 /* Cgroup v2 pseudo FS */
	CIFS_MAGIC_NUMBER     = 0xff534d42
	CODA_SUPER_MAGIC      = 0x73757245
	COH_SUPER_MAGIC       = 0x012ff7b7
	CRAMFS_MAGIC          = 0x28cd3d45
	DEBUGFS_MAGIC         = 0x64626720
	DEVFS_SUPER_MAGIC     = 0x1373 /* Linux 2.6.17 and earlier */
	DEVPTS_SUPER_MAGIC    = 0x1cd1
	ECRYPTFS_SUPER_MAGIC  = 0xf15f
	EFIVARFS_MAGIC        = 0xde5e81e4
	EFS_SUPER_MAGIC       = 0x00414a53
	EXT_SUPER_MAGIC       = 0x137d /* Linux 2.0 and earlier */
	EXT2_OLD_SUPER_MAGIC  = 0xef51
	EXT2_SUPER_MAGIC      = 0xef53
	EXT3_SUPER_MAGIC      = 0xef53
	EXT4_SUPER_MAGIC      = 0xef53
	F2FS_SUPER_MAGIC      = 0xf2f52010
	FUSE_SUPER_MAGIC      = 0x65735546
	FUTEXFS_SUPER_MAGIC   = 0xbad1dea /* Unused */
	HFS_SUPER_MAGIC       = 0x4244
	HOSTFS_SUPER_MAGIC    = 0x00c0ffee
	HPFS_SUPER_MAGIC      = 0xf995e849
	HUGETLBFS_MAGIC       = 0x958458f6
	ISOFS_SUPER_MAGIC     = 0x9660
	JFFS2_SUPER_MAGIC     = 0x72b6
	JFS_SUPER_MAGIC       = 0x3153464a
	MINIX_SUPER_MAGIC     = 0x137f     /* original minix FS */
	MINIX_SUPER_MAGIC2    = 0x138f     /* 30 char minix FS */
	MINIX2_SUPER_MAGIC    = 0x2468     /* minix V2 FS */
	MINIX2_SUPER_MAGIC2   = 0x2478     /* minix V2 FS, 30 char names */
	MINIX3_SUPER_MAGIC    = 0x4d5a     /* minix V3 FS, 60 char names */
	MQUEUE_MAGIC          = 0x19800202 /* POSIX message queue FS */
	MSDOS_SUPER_MAGIC     = 0x4d44
	MTD_INODE_FS_MAGIC    = 0x11307854
	NCP_SUPER_MAGIC       = 0x564c
	NFS_SUPER_MAGIC       = 0x6969
	NILFS_SUPER_MAGIC     = 0x3434
	NSFS_MAGIC            = 0x6e736673
	NTFS_SB_MAGIC         = 0x5346544e
	OCFS2_SUPER_MAGIC     = 0x7461636f
	OPENPROM_SUPER_MAGIC  = 0x9fa1
	OVERLAYFS_SUPER_MAGIC = 0x794c7630
	PIPEFS_MAGIC          = 0x50495045
	PROC_SUPER_MAGIC      = 0x9fa0 /* /proc FS */
	PSTOREFS_MAGIC        = 0x6165676c
	QNX4_SUPER_MAGIC      = 0x002f
	QNX6_SUPER_MAGIC      = 0x68191122
	RAMFS_MAGIC           = 0x858458f6
	REISERFS_SUPER_MAGIC  = 0x52654973
	ROMFS_MAGIC           = 0x7275
	SECURITYFS_MAGIC      = 0x73636673
	SELINUX_MAGIC         = 0xf97cff8c
	SMACK_MAGIC           = 0x43415d53
	SMB_SUPER_MAGIC       = 0x517b
	SMB2_MAGIC_NUMBER     = 0xfe534d42
	SOCKFS_MAGIC          = 0x534f434b
	SQUASHFS_MAGIC        = 0x73717368
	SYSFS_MAGIC           = 0x62656572
	SYSV2_SUPER_MAGIC     = 0x012ff7b6
	SYSV4_SUPER_MAGIC     = 0x012ff7b5
	TMPFS_MAGIC           = 0x01021994
	TRACEFS_MAGIC         = 0x74726163
	UDF_SUPER_MAGIC       = 0x15013346
	UFS_MAGIC             = 0x00011954
	USBDEVICE_SUPER_MAGIC = 0x9fa2
	V9FS_MAGIC            = 0x01021997
	VXFS_SUPER_MAGIC      = 0xa501fcf5
	XENFS_SUPER_MAGIC     = 0xabba1974
	XENIX_SUPER_MAGIC     = 0x012ff7b4
	XFS_SUPER_MAGIC       = 0x58465342
	_XIAFS_SUPER_MAGIC    = 0x012fd16d /* Linux 2.0 and earlier */
)

var FileSystems = map[int64]string{
	ADFS_SUPER_MAGIC:      "ADFS",
	AFFS_SUPER_MAGIC:      "AFFS",
	AFS_SUPER_MAGIC:       "AFS",
	ANON_INODE_FS_MAGIC:   "ANON",
	AUTOFS_SUPER_MAGIC:    "AUTOFS",
	BDEVFS_MAGIC:          "BDEVFS",
	BEFS_SUPER_MAGIC:      "BEFS",
	BFS_MAGIC:             "BFS",
	BINFMTFS_MAGIC:        "BINFMTFS",
	BPF_FS_MAGIC:          "BPF",
	BTRFS_SUPER_MAGIC:     "BTRFS",
	BTRFS_TEST_MAGIC:      "BTRFS",
	CGROUP_SUPER_MAGIC:    "CGROUP",
	CGROUP2_SUPER_MAGIC:   "CGROUP2",
	CIFS_MAGIC_NUMBER:     "CIFS",
	CODA_SUPER_MAGIC:      "CODA",
	COH_SUPER_MAGIC:       "COH",
	CRAMFS_MAGIC:          "CRAMFS",
	DEBUGFS_MAGIC:         "DEBUGFS",
	DEVFS_SUPER_MAGIC:     "DEVFS",
	DEVPTS_SUPER_MAGIC:    "DEVPTS",
	ECRYPTFS_SUPER_MAGIC:  "ECRYPTFS",
	EFIVARFS_MAGIC:        "EFIVARFS",
	EFS_SUPER_MAGIC:       "EFS",
	EXT_SUPER_MAGIC:       "EXT",
	EXT2_OLD_SUPER_MAGIC:  "EXT2",
	EXT2_SUPER_MAGIC:      "EXT2/3/4",
	F2FS_SUPER_MAGIC:      "F2FS",
	FUSE_SUPER_MAGIC:      "FUSE",
	FUTEXFS_SUPER_MAGIC:   "FUTEXFS",
	HFS_SUPER_MAGIC:       "HFS",
	HOSTFS_SUPER_MAGIC:    "HOSTFS",
	HPFS_SUPER_MAGIC:      "HPFS",
	HUGETLBFS_MAGIC:       "HUGETLBFS",
	ISOFS_SUPER_MAGIC:     "ISOFS",
	JFFS2_SUPER_MAGIC:     "JFFS2",
	JFS_SUPER_MAGIC:       "JFS",
	MINIX_SUPER_MAGIC:     "MINIX",
	MINIX_SUPER_MAGIC2:    "MINIX",
	MINIX2_SUPER_MAGIC:    "MINIX2",
	MINIX2_SUPER_MAGIC2:   "MINIX2",
	MINIX3_SUPER_MAGIC:    "MINIX3",
	MQUEUE_MAGIC:          "MQUEUE",
	MSDOS_SUPER_MAGIC:     "MSDOS",
	MTD_INODE_FS_MAGIC:    "MTD",
	NCP_SUPER_MAGIC:       "NCP",
	NFS_SUPER_MAGIC:       "NFS",
	NILFS_SUPER_MAGIC:     "NILFS",
	NSFS_MAGIC:            "NSFS",
	NTFS_SB_MAGIC:         "NTFS",
	OCFS2_SUPER_MAGIC:     "OCFS2",
	OPENPROM_SUPER_MAGIC:  "OPENPROM",
	OVERLAYFS_SUPER_MAGIC: "OVERLAYFS",
	PIPEFS_MAGIC:          "PIPEFS",
	PROC_SUPER_MAGIC:      "PROC",
	PSTOREFS_MAGIC:        "PSTOREFS",
	QNX4_SUPER_MAGIC:      "QNX4",
	QNX6_SUPER_MAGIC:      "QNX6",
	RAMFS_MAGIC:           "RAMFS",
	REISERFS_SUPER_MAGIC:  "REISERFS",
	ROMFS_MAGIC:           "ROMFS",
	SECURITYFS_MAGIC:      "SECURITYFS",
	SELINUX_MAGIC:         "SELINUX",
	SMACK_MAGIC:           "SMACK",
	SMB_SUPER_MAGIC:       "SMB",
	SMB2_MAGIC_NUMBER:     "SMB2",
	SOCKFS_MAGIC:          "SOCKFS",
	SQUASHFS_MAGIC:        "SQUASHFS",
	SYSFS_MAGIC:           "SYSFS",
	SYSV2_SUPER_MAGIC:     "SYSV2",
	SYSV4_SUPER_MAGIC:     "SYSV4",
	TMPFS_MAGIC:           "TMPFS",
	TRACEFS_MAGIC:         "TRACEFS",
	UDF_SUPER_MAGIC:       "UDF",
	UFS_MAGIC:             "UFS",
	USBDEVICE_SUPER_MAGIC: "USBDEVICE",
	V9FS_MAGIC:            "V9FS",
	VXFS_SUPER_MAGIC:      "VXFS",
	XENFS_SUPER_MAGIC:     "XENFS",
	XENIX_SUPER_MAGIC:     "XENIX",
	XFS_SUPER_MAGIC:       "XFS",
	_XIAFS_SUPER_MAGIC:    "",
}

var ExcludeTypes = map[int64]bool{
	PROC_SUPER_MAGIC: true,
	SYSFS_MAGIC:      true,
}

func MountPointStatus(mountpoint string) (*unix.Statfs_t, error) {
	var statfs unix.Statfs_t
	err := unix.Statfs(mountpoint, &statfs)
	return &statfs, err
}

var FLAG_minsize = flag.String("s", "1m", "help message for flag n")
var FLAG_quiet = flag.Bool("q", false, "Silently dismiss errors")

var FLAG_human = flag.Bool("h", false, "Silently dismiss errors")
var FLAG_giga = flag.Bool("g", false, "Silently dismiss errors")
var FLAG_mega = flag.Bool("m", false, "Silently dismiss errors")

func main() {
	flag.Parse()
	minsize_int64, err := units.FromHumanSize(*FLAG_minsize)
	if err != nil {
		panic(err)
	}
	dirs := flag.Args()
	for _, dir := range dirs {

		ret, err := readDir(dir)
		if err == nil && ret != nil {
			ret.displayMap("", minsize_int64, false)
		}
	}

}
