/*
 * dfu-util
 *
 * (C) 2007-2008 by OpenMoko, Inc.
 * (C) 2013 Hans Petter Selasky <hps@bitfrost.no>
 *
 * Written by Harald Welte <laforge@openmoko.org>
 *
 * Based on existing code of dfu-programmer-0.4
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <libusb.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "portable.h"
#include "dfu.h"
#include "usb_dfu.h"
#include "dfu_file.h"
#include "dfu_load.h"
#include "dfu_util.h"
#include "dfuse.h"
#include "quirks.h"

#ifdef HAVE_USBPATH_H
#include <usbpath.h>
#endif

int verbose = 0;

/* USB string descriptor should contain max 126 UTF-16 characters
 * but 253 would even accomodate any UTF-8 encoding */
#define MAX_DESC_STR_LEN 253

/* Find DFU interfaces in a given device.
 * Iterate through all DFU interfaces and their alternate settings
 * and call the passed handler function on each setting until handler
 * returns non-zero. */
static int find_dfu_if(libusb_device *dev,
		       int (*handler)(struct dfu_if *, void *),
		       void *v)
{
	struct libusb_device_descriptor desc;
	struct libusb_config_descriptor *cfg;
	const struct libusb_interface_descriptor *intf;
	const struct libusb_interface *uif;
	struct dfu_if _dif, *dfu_if = &_dif;
	int cfg_idx, intf_idx, alt_idx;
	int rc;

	memset(dfu_if, 0, sizeof(*dfu_if));
	rc = libusb_get_device_descriptor(dev, &desc);
	if (rc)
		return rc;
	for (cfg_idx = 0; cfg_idx < desc.bNumConfigurations;
	     cfg_idx++) {
		rc = libusb_get_config_descriptor(dev, cfg_idx, &cfg);
		if (rc)
			return rc;
		/* in some cases, noticably FreeBSD if uid != 0,
		 * the configuration descriptors are empty */
		if (!cfg)
			return 0;
		for (intf_idx = 0; intf_idx < cfg->bNumInterfaces;
		     intf_idx++) {
			uif = &cfg->interface[intf_idx];
			if (!uif)
				return 0;
			for (alt_idx = 0;
			     alt_idx < uif->num_altsetting; alt_idx++) {
				intf = &uif->altsetting[alt_idx];
				if (!intf)
					return 0;
				if (intf->bInterfaceClass == 0xfe &&
				    intf->bInterfaceSubClass == 1) {
					dfu_if->dev = dev;
					dfu_if->vendor = desc.idVendor;
					dfu_if->product = desc.idProduct;
					dfu_if->bcdDevice = desc.bcdDevice;
					dfu_if->configuration = cfg->
							bConfigurationValue;
					dfu_if->interface =
						intf->bInterfaceNumber;
					dfu_if->altsetting =
						intf->bAlternateSetting;
					if (intf->bInterfaceProtocol == 2)
						dfu_if->flags |= DFU_IFF_DFU;
					else
						dfu_if->flags &= ~DFU_IFF_DFU;
					if (!handler)
						return 1;
					rc = handler(dfu_if, v);
					if (rc != 0)
						return rc;
				}
			}
		}

		libusb_free_config_descriptor(cfg);
	}

	return 0;
}

static int _get_first_cb(struct dfu_if *dif, void *v)
{
	struct dfu_if *v_dif = (struct dfu_if*) v;

	/* Copy everything except the device handle.
	 * This depends heavily on this member being last! */
	memcpy(v_dif, dif, sizeof(*v_dif)-sizeof(libusb_device_handle *));

	/* return a value that makes find_dfu_if return immediately */
	return 1;
}

/* Fills in dif with the first found DFU interface */
static int get_first_dfu_if(struct dfu_if *dif)
{
	return find_dfu_if(dif->dev, &_get_first_cb, (void *) dif);
}

static int _check_match_cb(struct dfu_if *dif, void *v)
{
	struct dfu_if *v_dif = (struct dfu_if*) v;

	if (v_dif->flags & DFU_IFF_IFACE && 
	    dif->interface != v_dif->interface)
		return 0;
	if (v_dif->flags & DFU_IFF_ALT &&
	    dif->altsetting != v_dif->altsetting)
		return 0;
	return _get_first_cb(dif, v);
}

/* Fills in dif from the matching DFU interface/altsetting */
static int get_matching_dfu_if(struct dfu_if *dif)
{
	return find_dfu_if(dif->dev, &_check_match_cb, (void *) dif);
}

static int _count_match_cb(struct dfu_if *dif, void *v)
{
	struct dfu_if *v_dif = (struct dfu_if*) v;

	if (v_dif->flags & DFU_IFF_IFACE && 
	    dif->interface != v_dif->interface)
		return 0;
	if (v_dif->flags & DFU_IFF_ALT &&
	    dif->altsetting != v_dif->altsetting)
		return 0;
	v_dif->count++;
	return 0;
}

/* Count matching DFU interface/altsetting */
static int count_matching_dfu_if(struct dfu_if *dif)
{
	dif->count = 0;
	find_dfu_if(dif->dev, &_count_match_cb, (void *) dif);
	return dif->count;
}

/* Retrieves alternate interface name string.
 * Returns string length, or negative on error */
static int get_alt_name(struct dfu_if *dfu_if, unsigned char *name)
{
	libusb_device *dev = dfu_if->dev;
	struct libusb_config_descriptor *cfg;
	int alt_name_str_idx;
	int ret;

	ret = libusb_get_config_descriptor_by_value(dev, dfu_if->configuration,
						    &cfg);
	if (ret)
		return ret;

	alt_name_str_idx = cfg->interface[dfu_if->interface].
			       altsetting[dfu_if->altsetting].iInterface;
	ret = -1;
	if (alt_name_str_idx) {
		if (!dfu_if->dev_handle)
			if (libusb_open(dfu_if->dev, &dfu_if->dev_handle))
				dfu_if->dev_handle = NULL;
		if (dfu_if->dev_handle)
			ret = libusb_get_string_descriptor_ascii(
					dfu_if->dev_handle, alt_name_str_idx,
					name, MAX_DESC_STR_LEN);
	}
	libusb_free_config_descriptor(cfg);
	return ret;
}

static int print_dfu_if(struct dfu_if *dfu_if, void *v)
{
	unsigned char name[MAX_DESC_STR_LEN+1] = "UNDEFINED";

	get_alt_name(dfu_if, name);

	printf("Found %s: [%04x:%04x] devnum=%u, cfg=%u, intf=%u, "
	       "alt=%u, name=\"%s\"\n", 
	       dfu_if->flags & DFU_IFF_DFU ? "DFU" : "Runtime",
	       dfu_if->vendor, dfu_if->product, dfu_if->devnum,
	       dfu_if->configuration, dfu_if->interface,
	       dfu_if->altsetting, name);
	return 0;
}

/* Walk the device tree and print out DFU devices */
static int list_dfu_interfaces(libusb_context *ctx)
{
	libusb_device **list;
	libusb_device *dev;
	ssize_t num_devs, i;

	num_devs = libusb_get_device_list(ctx, &list);

	for (i = 0; i < num_devs; ++i) {
		dev = list[i];
		find_dfu_if(dev, &print_dfu_if, NULL);
	}

	libusb_free_device_list(list, 1);
	return 0;
}

static int alt_by_name(struct dfu_if *dfu_if, void *v)
{
	unsigned char name[MAX_DESC_STR_LEN+1];

	if (get_alt_name(dfu_if, name) < 0)
		return 0;
	if (strcmp((char *)name, v))
		return 0;
	/*
	 * Return altsetting+1 so that we can use return value 0 to indicate
	 * "not found".
	 */
	return dfu_if->altsetting+1;
}

static int _count_cb(struct dfu_if *dif, void *v)
{
	int *count = (int*) v;

	(*count)++;

	return 0;
}

/* Count DFU interfaces within a single device */
static int count_dfu_interfaces(libusb_device *dev)
{
	int num_found = 0;

	find_dfu_if(dev, &_count_cb, (void *) &num_found);

	return num_found;
}


/* Iterate over all matching DFU capable devices within system */
static int iterate_dfu_devices(libusb_context *ctx, struct dfu_if *dif,
    int (*action)(struct libusb_device *dev, void *user), void *user)
{
	libusb_device **list;
	ssize_t num_devs, i;

	num_devs = libusb_get_device_list(ctx, &list);
	for (i = 0; i < num_devs; ++i) {
		int retval;
		struct libusb_device_descriptor desc;
		struct libusb_device *dev = list[i];

		if (dif && (dif->flags & DFU_IFF_DEVNUM) &&
		    (libusb_get_bus_number(dev) != dif->bus ||
		     libusb_get_device_address(dev) != dif->devnum))
			continue;
		if (libusb_get_device_descriptor(dev, &desc))
			continue;
		if (dif && (dif->flags & DFU_IFF_VENDOR) &&
		    desc.idVendor != dif->vendor)
			continue;
		if (dif && (dif->flags & DFU_IFF_PRODUCT) &&
		    desc.idProduct != dif->product)
			continue;
		if (!count_dfu_interfaces(dev))
			continue;

		retval = action(dev, user);
		if (retval) {
			libusb_free_device_list(list, 0);
			return retval;
		}
	}
	libusb_free_device_list(list, 0);
	return 0;
}


static int found_dfu_device(struct libusb_device *dev, void *user)
{
	struct dfu_if *dif = (struct dfu_if*) user;

	dif->dev = dev;
	return 1;
}


/* Find the first DFU-capable device, save it in dfu_if->dev */
static int get_first_dfu_device(libusb_context *ctx, struct dfu_if *dif)
{
	return iterate_dfu_devices(ctx, dif, found_dfu_device, dif);
}


static int count_one_dfu_device(struct libusb_device *dev, void *user)
{
	int *num = (int*) user;

	(*num)++;
	return 0;
}


/* Count DFU capable devices within system */
static int count_dfu_devices(libusb_context *ctx, struct dfu_if *dif)
{
	int num_found = 0;

	iterate_dfu_devices(ctx, dif, count_one_dfu_device, &num_found);
	return num_found;
}


static void parse_vendprod(uint16_t *vendor, uint16_t *product,
			   const char *str)
{
	const char *colon;

	*vendor = strtoul(str, NULL, 16);
	colon = strchr(str, ':');
	if (colon)
		*product = strtoul(colon + 1, NULL, 16);
	else
		*product = 0;
}


#ifdef HAVE_USBPATH_H

static int resolve_device_path(struct dfu_if *dif)
{
	int res;

	res = usb_path2devnum(dif->path);
	if (res < 0)
		return -EINVAL;
	if (!res)
		return 0;

	dif->bus = atoi(dif->path);
	dif->devnum = res;
	dif->flags |= DFU_IFF_DEVNUM;
	return res;
}

#else /* HAVE_USBPATH_H */

static int resolve_device_path(struct dfu_if *dif)
{
	fprintf(stderr,
	    "USB device paths are not supported by this dfu-util.\n");
	exit(1);
}

#endif /* !HAVE_USBPATH_H */

/* Look for a descriptor in a concatenated descriptor list
 * Will return desc_index'th match of given descriptor type
 * Returns length of found descriptor, limited to res_size */
static int find_descriptor(const unsigned char *desc_list, int list_len,
			   uint8_t desc_type, uint8_t desc_index,
			   uint8_t *res_buf, int res_size)
{
	int p = 0;
	int hit = 0;

	while (p + 1 < list_len) {
		int desclen;

		desclen = (int) desc_list[p];
		if (desclen == 0) {
			fprintf(stderr, "Error: Invalid descriptor list\n");
			return -1;
		}
		if (desc_list[p + 1] == desc_type && hit++ == desc_index) {
			if (desclen > res_size)
				desclen = res_size;
			if (p + desclen > list_len)
				desclen = list_len - p;
			memcpy(res_buf, &desc_list[p], desclen);
			return desclen;
		}
		p += (int) desc_list[p];
	}
	return 0;
}

/* Look for a descriptor in the active configuration
 * Will also find extra descriptors which are normally
 * not returned by the standard libusb_get_descriptor() */
static int usb_get_any_descriptor(struct libusb_device_handle *dev_handle,
				  uint8_t desc_type,
				  uint8_t desc_index,
				  unsigned char *resbuf, int res_len)
{
	struct libusb_device *dev;
	struct libusb_config_descriptor *config;
	int ret;
	uint16_t conflen;
	unsigned char *cbuf;

	dev = libusb_get_device(dev_handle);
	if (!dev) {
		fprintf(stderr, "Error: Broken device handle\n");
		return -1;
	}
	/* Get the total length of the configuration descriptors */
	ret = libusb_get_active_config_descriptor(dev, &config);
	if (ret == LIBUSB_ERROR_NOT_FOUND) {
		fprintf(stderr, "Error: Device is unconfigured\n");
		return -1;
	} else if (ret) {
		fprintf(stderr, "Error: failed "
			"libusb_get_active_config_descriptor()\n");
		exit(1);
	}
	conflen = config->wTotalLength;
	libusb_free_config_descriptor(config);

	/* Suck in the configuration descriptor list from device */
	cbuf = malloc(conflen);
	ret = libusb_get_descriptor(dev_handle, LIBUSB_DT_CONFIG,
				    desc_index, cbuf, conflen);
	if (ret < conflen) {
		fprintf(stderr, "Warning: failed to retrieve complete "
			"configuration descriptor, got %i/%i\n",
			ret, conflen);
		conflen = ret;
	}
	/* Search through the configuration descriptor list */
	ret = find_descriptor(cbuf, conflen, desc_type, desc_index,
			      resbuf, res_len);
	free(cbuf);

	/* A descriptor must be at least 2 bytes long */
	if (ret > 1) {
		if (verbose)
			printf("Found descriptor in complete configuration "
			       "descriptor list\n");
		return ret;
	}

	/* Finally try to retrieve it requesting the device directly
	 * This is not supported on all devices for non-standard types */
	return libusb_get_descriptor(dev_handle, desc_type, desc_index,
				     resbuf, res_len);
}

/* Get cached extra descriptor from libusb for an interface
 * Returns length of found descriptor */
static int get_cached_extra_descriptor(struct libusb_device *dev,
				       uint8_t bConfValue,
				       uint8_t intf,
				       uint8_t desc_type, uint8_t desc_index,
				       unsigned char *resbuf, int res_len)
{
	struct libusb_config_descriptor *cfg;
	const unsigned char *extra;
	int extra_len;
	int ret;
	int alt;

	ret = libusb_get_config_descriptor_by_value(dev, bConfValue, &cfg);
	if (ret == LIBUSB_ERROR_NOT_FOUND) {
		fprintf(stderr, "Error: Device is unconfigured\n");
		return -1;
	} else if (ret) {
		fprintf(stderr, "Error: failed "
			"libusb_config_descriptor_by_value()\n");
		exit(1);
	}

	/* Extra descriptors can be shared between alternate settings but
	 * libusb may attach them to one setting. Therefore go through all.
	 * Note that desc_index is per alternate setting, hits will not be
	 * counted from one to another */
	for (alt = 0; alt < cfg->interface[intf].num_altsetting;
	     alt++) {
		extra = cfg->interface[intf].altsetting[alt].extra;
		extra_len = cfg->interface[intf].altsetting[alt].extra_length;
		if (extra_len > 1)
			ret = find_descriptor(extra, extra_len, desc_type,
					      desc_index, resbuf, res_len);
		if (ret > 1)
			break;
	}
	libusb_free_config_descriptor(cfg);
	if (ret < 2 && verbose)
		printf("Did not find cached descriptor\n");
	return ret;
}

static void help(void)
{
	fprintf(stderr, "Usage: dfu-util [options] ...\n"
		"  -h --help\t\t\tPrint this help message\n"
		"  -V --version\t\t\tPrint the version number\n"
		"  -v --verbose\t\t\tPrint verbose debug statements\n"
		"  -l --list\t\t\tList the currently attached DFU capable USB devices\n");
	printf(	"  -e --detach\t\t\tDetach the currently attached DFU capable USB devices\n"
		"  -d --device vendor:product\tSpecify Vendor/Product ID of DFU device\n"
		"  -p --path bus-port. ... .port\tSpecify path to DFU device\n"
		"  -c --cfg config_nr\t\tSpecify the Configuration of DFU device\n"
		"  -i --intf intf_nr\t\tSpecify the DFU Interface number\n"
		"  -a --alt alt\t\t\tSpecify the Altsetting of the DFU Interface\n"
		"\t\t\t\tby name or by number\n");
	printf(	"  -t --transfer-size\t\tSpecify the number of bytes per USB Transfer\n"
		"  -U --upload file\t\tRead firmware from device into <file>\n"
		"  -D --download file\t\tWrite firmware from <file> into device\n"
		"  -R --reset\t\t\tIssue USB Reset signalling once we're finished\n"
		"  -s --dfuse-address address\tST DfuSe mode, specify target address for\n"
		"\t\t\t\traw file download or upload. Not applicable for\n"
		"\t\t\t\tDfuSe file (.dfu) downloads\n"
		);
	exit(EX_USAGE);
}

static void print_version(void)
{
	printf(PACKAGE_STRING "\n\n");
	printf("Copyright 2005-2008 Weston Schmidt, Harald Welte and OpenMoko Inc.\n"
	       "Copyright 2010-2012 Tormod Volden and Stefan Schmidt\n"
	       "This program is Free Software and has ABSOLUTELY NO WARRANTY\n"
	       "Please report bugs to " PACKAGE_BUGREPORT "\n\n");
}

static struct option opts[] = {
	{ "help", 0, 0, 'h' },
	{ "version", 0, 0, 'V' },
	{ "verbose", 0, 0, 'v' },
	{ "list", 0, 0, 'l' },
	{ "detach", 0, 0, 'e' },
	{ "detach-delay", 1, 0, 'E' },
	{ "device", 1, 0, 'd' },
	{ "path", 1, 0, 'p' },
	{ "configuration", 1, 0, 'c' },
	{ "cfg", 1, 0, 'c' },
	{ "interface", 1, 0, 'i' },
	{ "intf", 1, 0, 'i' },
	{ "altsetting", 1, 0, 'a' },
	{ "alt", 1, 0, 'a' },
	{ "serial", 1, 0, 'S' },
	{ "transfer-size", 1, 0, 't' },
	{ "upload", 1, 0, 'U' },
	{ "upload-size", 1, 0, 'Z' },
	{ "download", 1, 0, 'D' },
	{ "reset", 0, 0, 'R' },
	{ "dfuse-address", 1, 0, 's' }
};

enum mode {
	MODE_NONE,
	MODE_VERSION,
	MODE_LIST,
	MODE_DETACH,
	MODE_UPLOAD,
	MODE_DOWNLOAD
};

int main(int argc, char **argv)
{
	int expected_size = 0;
	unsigned int transfer_size = 0;
	enum mode mode = MODE_NONE;
	struct dfu_status status;
	struct usb_dfu_func_descriptor func_dfu = {0}, func_dfu_rt = {0};
	libusb_context *ctx;
	struct dfu_file file;
	char *end;
	int final_reset = 0;
	int ret;
	int dfuse_device = 0;
	int fd;
	const char *dfuse_options = NULL;
	int detach_delay = 5;
	int dfu_has_suffix = 1;
	uint16_t runtime_vendor;
	uint16_t runtime_product;

	memset(&file, 0, sizeof(file));

	/* make sure all prints are flushed */
	setvbuf(stdout, NULL, _IONBF, 0);

	while (1) {
		int c, option_index = 0;
		c = getopt_long(argc, argv, "hVvled:p:c:i:a:t:U:D:Rs:", opts,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			help();
			break;
		case 'V':
			mode = MODE_VERSION;
			break;
		case 'v':
			verbose++;
			break;
		case 'l':
			mode = MODE_LIST;
			break;
		case 'e':
			mode = MODE_DETACH;
			match_iface_alt_index = 0;
			match_iface_index = 0;
			break;
		case 'E':
			detach_delay = atoi(optarg);
			break;
		case 'd':
			parse_vendprod(optarg);
			break;
		case 'p':
			/* Parse device path */
			ret = resolve_device_path(optarg);
			if (ret < 0)
				errx(EX_SOFTWARE, "Unable to parse '%s'", optarg);
			if (!ret)
				errx(EX_SOFTWARE, "Cannot find '%s'", optarg);
			break;
		case 'c':
			/* Configuration */
			match_config_index = atoi(optarg);
			break;
		case 'i':
			/* Interface */
			match_iface_index = atoi(optarg);
			break;
		case 'a':
			/* Interface Alternate Setting */
			dif->altsetting = strtoul(optarg, &end, 0);
			if (*end)
				alt_name = optarg;
			dif->flags |= DFU_IFF_ALT;
			break;
		case 't':
			transfer_size = atoi(optarg);
			break;
		case 'U':
			mode = MODE_UPLOAD;
			file.name = optarg;
			break;
		case 'Z':
			expected_size = atoi(optarg);
			break;
		case 'D':
			mode = MODE_DOWNLOAD;
			file.name = optarg;
			break;
		case 'R':
			final_reset = 1;
			break;
		case 's':
			dfuse_options = optarg;
			dfu_has_suffix = 0;
			break;
		default:
			help();
			break;
		}
	}

	print_version();
	if (mode == MODE_VERSION) {
		exit(0);
	}

	if (mode == MODE_NONE) {
		fprintf(stderr, "You need to specify one of -D or -U\n");
		help();
	}

	if (mode == MODE_DOWNLOAD) {
		dfu_load_file(&file, dfu_has_suffix, 0);
		/* If the user didn't specify product and/or vendor IDs to match,
		 * use any IDs from the file suffix for device matching */
		if (match_vendor < 0 && file.idVendor != 0xffff) {
			match_vendor = file.idVendor;
			printf("Match vendor ID from file: %04x\n", match_vendor);
		}
		if (match_product < 0 && file.idProduct != 0xffff) {
			match_product = file.idProduct;
			printf("Match product ID from file: %04x\n", match_product);
		}
	}

	ret = libusb_init(&ctx);
	if (ret)
		errx(EX_IOERR, "unable to initialize libusb: %i", ret);

	if (verbose > 2) {
		libusb_set_debug(ctx, 255);
	}

	probe_devices(ctx);

	if (mode == MODE_LIST) {
		list_dfu_interfaces();
		exit(0);
	}

	if (dfu_root == NULL) {
		errx(EX_IOERR, "No DFU capable USB device found");
	} else if (dfu_root->next != NULL) {
		/* We cannot safely support more than one DFU capable device
		 * with same vendor/product ID, since during DFU we need to do
		 * a USB bus reset, after which the target device will get a
		 * new address */
		errx(EX_IOERR, "More than one DFU capable USB device found! "
		       "Try `--list' and specify the serial number "
		       "or disconnect all but one device\n");
	}

	/* We have exactly one device. Its libusb_device is now in dfu_root->dev */

	printf("Opening DFU capable USB device...\n");
	ret = libusb_open(dfu_root->dev, &dfu_root->dev_handle);
	if (ret || !dfu_root->dev_handle)
		errx(EX_IOERR, "Cannot open device");

	printf("ID %04x:%04x\n", dfu_root->vendor, dfu_root->product);

	printf("Run-time device DFU version %04x\n",
	       libusb_le16_to_cpu(dfu_root->func_dfu.bcdDFUVersion));

	/* Transition from run-Time mode to DFU mode */
	if (!(dfu_root->flags & DFU_IFF_DFU)) {
		int err;
		/* In the 'first round' during runtime mode, there can only be one
		* DFU Interface descriptor according to the DFU Spec. */

		/* FIXME: check if the selected device really has only one */

		runtime_vendor = dfu_root->vendor;
		runtime_product = dfu_root->product;

		printf("Claiming USB DFU Runtime Interface...\n");
		if (libusb_claim_interface(dfu_root->dev_handle, dfu_root->interface) < 0) {
			errx(EX_IOERR, "Cannot claim interface %d",
				dfu_root->interface);
		}

		if (libusb_set_interface_alt_setting(dfu_root->dev_handle, dfu_root->interface, 0) < 0) {
			errx(EX_IOERR, "Cannot set alt interface zero");
		}

		printf("Determining device status: ");

		err = dfu_get_status(dfu_root->dev_handle, dfu_root->interface, &status);
		if (err == LIBUSB_ERROR_PIPE) {
			printf("Device does not implement get_status, assuming appIDLE\n");
			status.bStatus = DFU_STATUS_OK;
			status.bwPollTimeout = 0;
			status.bState  = DFU_STATE_appIDLE;
			status.iString = 0;
		} else if (err < 0) {
			errx(EX_IOERR, "error get_status");
		} else {
			printf("state = %s, status = %d\n",
			       dfu_state_to_string(status.bState), status.bStatus);
		}

		if (!(dfu_root->quirks & QUIRK_POLLTIMEOUT))
			milli_sleep(status.bwPollTimeout);

		switch (status.bState) {
		case DFU_STATE_appIDLE:
		case DFU_STATE_appDETACH:
			printf("Device really in Runtime Mode, send DFU "
			       "detach request...\n");
			if (dfu_detach(dfu_root->dev_handle,
				       dfu_root->interface, 1000) < 0) {
				errx(EX_IOERR, "error detaching");
			}
			libusb_release_interface(dfu_root->dev_handle,
						 dfu_root->interface);
			if (dfu_root->func_dfu.bmAttributes & USB_DFU_WILL_DETACH) {
				printf("Device will detach and reattach...\n");
			} else {
				printf("Resetting USB...\n");
				ret = libusb_reset_device(dfu_root->dev_handle);
				if (ret < 0 && ret != LIBUSB_ERROR_NOT_FOUND)
					errx(EX_IOERR, "error resetting "
						"after detach");
			}
			break;
		case DFU_STATE_dfuERROR:
			printf("dfuERROR, clearing status\n");
			if (dfu_clear_status(dfu_root->dev_handle,
					     dfu_root->interface) < 0) {
				errx(EX_IOERR, "error clear_status");
			}
			/* fall through */
		default:
			warnx("WARNING: Runtime device already in DFU state ?!?");
			goto dfustate;
			break;
		}
		libusb_release_interface(dfu_root->dev_handle,
					 dfu_root->interface);
		libusb_close(dfu_root->dev_handle);
		dfu_root->dev_handle = NULL;

		if (mode == MODE_DETACH) {
			libusb_exit(ctx);
			exit(0);
		}

		/* keeping handles open might prevent re-enumeration */
		disconnect_devices();

		milli_sleep(detach_delay * 1000);

		/* Change match vendor and product to impossible values to force
		 * only DFU mode matches in the following probe */
		match_vendor = match_product = 0x10000;

		probe_devices(ctx);

		if (dfu_root == NULL) {
			errx(EX_IOERR, "Lost device after RESET?");
		} else if (dfu_root->next != NULL) {
			errx(EX_IOERR, "More than one DFU capable USB device found! "
				"Try `--list' and specify the serial number "
				"or disconnect all but one device");
		}

		/* Check for DFU mode device */
		if (!(dfu_root->flags | DFU_IFF_DFU))
			errx(EX_SOFTWARE, "Device is not in DFU mode");

		printf("Opening DFU USB Device...\n");
		ret = libusb_open(dfu_root->dev, &dfu_root->dev_handle);
		if (ret || !dfu_root->dev_handle) {
			errx(EX_IOERR, "Cannot open device");
		}
	} else {
		/* we're already in DFU mode, so we can skip the detach/reset
		 * procedure */
		/* If a match vendor/product was specified, use that as the runtime
		 * vendor/product, otherwise use the DFU mode vendor/product */
		runtime_vendor = match_vendor < 0 ? dfu_root->vendor : match_vendor;
		runtime_product = match_product < 0 ? dfu_root->product : match_product;
	}

dfustate:
#if 0
	printf("Setting Configuration %u...\n", dfu_root->configuration);
	if (libusb_set_configuration(dfu_root->dev_handle, dfu_root->configuration) < 0) {
		errx(EX_IOERR, "Cannot set configuration");
	}
#endif
	printf("Claiming USB DFU Interface...\n");
	if (libusb_claim_interface(dfu_root->dev_handle, dfu_root->interface) < 0) {
		errx(EX_IOERR, "Cannot claim interface");
	}

	printf("Setting Alternate Setting #%d ...\n", dfu_root->altsetting);
	if (libusb_set_interface_alt_setting(dfu_root->dev_handle, dfu_root->interface, dfu_root->altsetting) < 0) {
		errx(EX_IOERR, "Cannot set alternate interface");
	}

status_again:
	printf("Determining device status: ");
	if (dfu_get_status(dfu_root->dev_handle, dfu_root->interface, &status ) < 0) {
		errx(EX_IOERR, "error get_status");
	}
	printf("state = %s, status = %d\n",
	       dfu_state_to_string(status.bState), status.bStatus);
	if (!(dfu_root->quirks & QUIRK_POLLTIMEOUT))
		milli_sleep(status.bwPollTimeout);

	switch (status.bState) {
	case DFU_STATE_appIDLE:
	case DFU_STATE_appDETACH:
		errx(EX_IOERR, "Device still in Runtime Mode!");
		break;
	case DFU_STATE_dfuERROR:
		printf("dfuERROR, clearing status\n");
		if (dfu_clear_status(dfu_root->dev_handle, dfu_root->interface) < 0) {
			errx(EX_IOERR, "error clear_status");
		}
		goto status_again;
		break;
	case DFU_STATE_dfuDNLOAD_IDLE:
	case DFU_STATE_dfuUPLOAD_IDLE:
		printf("aborting previous incomplete transfer\n");
		if (dfu_abort(dfu_root->dev_handle, dfu_root->interface) < 0) {
			errx(EX_IOERR, "can't send DFU_ABORT");
		}
		goto status_again;
		break;
	case DFU_STATE_dfuIDLE:
		printf("dfuIDLE, continuing\n");
		break;
	default:
		break;
	}

	if (DFU_STATUS_OK != status.bStatus ) {
		printf("WARNING: DFU Status: '%s'\n",
			dfu_status_to_string(status.bStatus));
		/* Clear our status & try again. */
		if (dfu_clear_status(dfu_root->dev_handle, dfu_root->interface) < 0)
			errx(EX_IOERR, "USB communication error");
		if (dfu_get_status(dfu_root->dev_handle, dfu_root->interface, &status) < 0)
			errx(EX_IOERR, "USB communication error");
		if (DFU_STATUS_OK != status.bStatus)
			errx(EX_SOFTWARE, "Status is not OK: %d", status.bStatus);
		if (!(dfu_root->quirks & QUIRK_POLLTIMEOUT))
			milli_sleep(status.bwPollTimeout);
	}

	printf("DFU mode device DFU version %04x\n",
	       libusb_le16_to_cpu(dfu_root->func_dfu.bcdDFUVersion));

	if (dfu_root->func_dfu.bcdDFUVersion == libusb_cpu_to_le16(0x11a))
		dfuse_device = 1;

	/* If not overridden by the user */
	if (!transfer_size) {
		transfer_size = libusb_le16_to_cpu(
		    dfu_root->func_dfu.wTransferSize);
		if (transfer_size) {
			printf("Device returned transfer size %i\n",
			       transfer_size);
		} else {
			errx(EX_IOERR, "Transfer size must be "
				"specified");
		}
	}

#ifdef HAVE_GETPAGESIZE
/* autotools lie when cross-compiling for Windows using mingw32/64 */
#ifndef __MINGW32__
	/* limitation of Linux usbdevio */
	if ((int)transfer_size > getpagesize()) {
		transfer_size = getpagesize();
		printf("Limited transfer size to %i\n", transfer_size);
	}
#endif /* __MINGW32__ */
#endif /* HAVE_GETPAGESIZE */

	if (transfer_size < dfu_root->bMaxPacketSize0) {
		transfer_size = dfu_root->bMaxPacketSize0;
		printf("Adjusted transfer size to %i\n", transfer_size);
	}

	switch (mode) {
	case MODE_UPLOAD:
		/* open for "exclusive" writing */
		fd = open(file.name, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, 0666);
		if (fd < 0)
			err(EX_IOERR, "Cannot open file %s for writing", file.name);

		if (dfuse_device || dfuse_options) {
		    if (dfuse_do_upload(dfu_root, transfer_size, fd,
					dfuse_options) < 0)
			exit(1);
		} else {
		    if (dfuload_do_upload(dfu_root, transfer_size,
			expected_size, fd) < 0) {
			exit(1);
		    }
		}
		close(fd);
		break;

	case MODE_DOWNLOAD:
		file.filep = fopen(file.name, "rb");
		if (file.filep == NULL) {
			perror(file.name);
			exit(1);
		}
		ret = parse_dfu_suffix(&file);
		if (ret < 0)
			exit(1);
		if (ret == 0) {
			fprintf(stderr, "Warning: File has no DFU suffix\n");
		} else if (file.bcdDFU != 0x0100 && file.bcdDFU != 0x11a) {
			fprintf(stderr, "Unsupported DFU file revision "
				"%04x\n", file.bcdDFU);
			exit(1);
		}
		if (file.idVendor != 0xffff &&
		    dif->vendor != file.idVendor) {
			fprintf(stderr, "Warning: File vendor ID %04x does "
				"not match device %04x\n", file.idVendor, dif->vendor);
		}
		if (file.idProduct != 0xffff &&
		    dif->product != file.idProduct) {
			fprintf(stderr, "Warning: File product ID %04x does "
				"not match device %04x\n", file.idProduct, dif->product);
		}
		if (dfuse_device || dfuse_options || file.bcdDFU == 0x11a) {
		        if (dfuse_do_dnload(dif, transfer_size, file,
							dfuse_options) < 0)
				exit(1);
		} else {
			if (dfuload_do_dnload(dif, transfer_size, file) < 0)
				exit(1);
	 	}
		break;
	case MODE_DETACH:
		if (dfu_detach(dfu_root->dev_handle, dfu_root->interface, 1000) < 0) {
			errx(EX_IOERR, "can't detach");
		}
		break;
	default:
		errx(EX_IOERR, "Unsupported mode: %u", mode);
		break;
	}

	if (final_reset) {
		if (dfu_detach(dfu_root->dev_handle, dfu_root->interface, 1000) < 0) {
			errx(EX_IOERR, "can't detach");
		}
		printf("Resetting USB to switch back to runtime mode\n");
		ret = libusb_reset_device(dfu_root->dev_handle);
		if (ret < 0 && ret != LIBUSB_ERROR_NOT_FOUND) {
			errx(EX_IOERR, "error resetting after download");
		}
	}

	libusb_close(dfu_root->dev_handle);
	dfu_root->dev_handle = NULL;
	libusb_exit(ctx);

	return (0);
}
