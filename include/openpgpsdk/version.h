#define OPS_VERSION_MAJOR	0
/* Set to the version next to be released */
#define OPS_VERSION_MINOR	0
/* 0 for development version, 1 for release */
#define OPS_VERSION_RELEASE	0

#define OPS_VERSION		((OPS_VERSION_MAJOR << 16)+(OPS_VERSION_MINOR << 1)+OPS_VERSION_RELEASE)

#if OPS_VERSION_RELEASE
# define OPS_DEV_STRING ""
#else
# define OPS_DEV_STRING " (dev)"
#endif


#define OPS_VERSION_CAT(a,b)	"OpenPGP:SDK v" #a "." #b OPS_DEV_STRING
#define OPS_VERSION_CAT2(a,b)	OPS_VERSION_CAT(a,b)
#define OPS_VERSION_STRING	OPS_VERSION_CAT2(OPS_VERSION_MAJOR,OPS_VERSION_MINOR)
