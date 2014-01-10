/*
 * Copyright (c) 2003 Sun Microsystems, Inc.  All Rights Reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistribution of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistribution in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of Sun Microsystems, Inc. or the names of
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * 
 * This software is provided "AS IS," without a warranty of any kind.
 * ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES,
 * INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE HEREBY EXCLUDED.
 * SUN MICROSYSTEMS, INC. ("SUN") AND ITS LICENSORS SHALL NOT BE LIABLE
 * FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING
 * OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.  IN NO EVENT WILL
 * SUN OR ITS LICENSORS BE LIABLE FOR ANY LOST REVENUE, PROFIT OR DATA,
 * OR FOR DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL, INCIDENTAL OR
 * PUNITIVE DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF
 * LIABILITY, ARISING OUT OF THE USE OF OR INABILITY TO USE THIS SOFTWARE,
 * EVEN IF SUN HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include <ipmitool/helper.h>
#include <ipmitool/log.h>
#include <ipmitool/ipmi.h>
#include <ipmitool/ipmi_intf.h>
#include <ipmitool/ipmi_session.h>
#include <ipmitool/ipmi_sdr.h>
#include <ipmitool/ipmi_gendev.h>
#include <ipmitool/ipmi_sel.h>
#include <ipmitool/ipmi_fru.h>
#include <ipmitool/ipmi_sol.h>
#include <ipmitool/ipmi_isol.h>
#include <ipmitool/ipmi_lanp.h>
#include <ipmitool/ipmi_chassis.h>
#include <ipmitool/ipmi_mc.h>
#include <ipmitool/ipmi_firewall.h>
#include <ipmitool/ipmi_sensor.h>
#include <ipmitool/ipmi_channel.h>
#include <ipmitool/ipmi_session.h>
#include <ipmitool/ipmi_event.h>
#include <ipmitool/ipmi_user.h>
#include <ipmitool/ipmi_raw.h>
#include <ipmitool/ipmi_pef.h>
#include <ipmitool/ipmi_oem.h>
#include <ipmitool/ipmi_ekanalyzer.h>
#include <ipmitool/ipmi_picmg.h>

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef ENABLE_ALL_OPTIONS
# define OPTION_STRING	"I:hVvcgsEKYao:H:d:P:f:U:p:C:L:A:t:T:m:z:S:l:b:B:e:k:y:O:R:N:D:"
#else
# define OPTION_STRING	"I:hVvcH:f:U:p:d:S:D:"
#endif

extern int verbose;
extern int csv_output;
extern const struct valstr ipmi_privlvl_vals[];
extern const struct valstr ipmi_authtype_session_vals[];

extern struct ipmi_cmd ipmitool_cmd_list[]; /* Bob: this is in ../src/ipmitool.c */

// Bob: this needs to be not a global single instance
static struct ipmi_intf * ipmi_main_intf = NULL;

/* ipmi_password_file_read  -  Open file and read password from it
 *
 * @filename:	file name to read from
 *
 * returns pointer to allocated buffer containing password
 *   (caller is expected to free when finished)
 * returns NULL on error
 */
static char *
ipmi_password_file_read(char * filename)
{
	FILE * fp;
	char * pass = NULL;
	int l;

	pass = malloc(21);
	if (pass == NULL) {
		lprintf(LOG_ERR, "ipmitool: malloc failure");
		return NULL;
	}

	memset(pass, 0, 21);
	fp = ipmi_open_file_read((const char *)filename);
	if (fp == NULL) {
		lprintf(LOG_ERR, "Unable to open password file %s",
				filename);
		free(pass);
		return NULL;
	}

	/* read in id */
	if (fgets(pass, 21, fp) == NULL) {
		lprintf(LOG_ERR, "Unable to read password from file %s",
				filename);
		free(pass);
		fclose(fp);
		return NULL;
	}

	/* remove trailing whitespace */
	l = strcspn(pass, " \r\n\t");
	if (l > 0) {
		pass[l] = '\0';
	}

	fclose(fp);
	return pass;
}


/*
 * Print all the commands in the above table to stderr
 * used for help text on command line and shell
 */
void
ipmi_cmd_print(struct ipmi_cmd * cmdlist)
{
	struct ipmi_cmd * cmd;
	int hdr = 0;

	if (cmdlist == NULL)
		return;
	for (cmd=cmdlist; cmd->func != NULL; cmd++) {
		if (cmd->desc == NULL)
			continue;
		if (hdr == 0) {
			lprintf(LOG_NOTICE, "Commands:");
			hdr = 1;
		}
		lprintf(LOG_NOTICE, "\t%-12s  %s", cmd->name, cmd->desc);
	}
	lprintf(LOG_NOTICE, "");
}

/* ipmi_cmd_run - run a command from list based on parameters
 *                called from main()
 *
 *                1. iterate through ipmi_cmd_list matching on name
 *                2. call func() for that command
 *
 * @intf:	ipmi interface
 * @name:	command name
 * @argc:	command argument count
 * @argv:	command argument list
 *
 * returns value from func() of that commnad if found
 * returns -1 if command is not found
 */
int
ipmi_cmd_run(struct ipmi_intf * intf, char * name, int argc, char ** argv)
{
	struct ipmi_cmd * cmd = intf->cmdlist;

	/* hook to run a default command if nothing specified */
	if (name == NULL) {
		if (cmd->func == NULL || cmd->name == NULL)
			return -1;
		else if (strncmp(cmd->name, "default", 7) == 0)
			return cmd->func(intf, 0, NULL);
		else {
			lprintf(LOG_ERR, "No command provided!");
			ipmi_cmd_print(intf->cmdlist);
			return -1;
		}
	}

	for (cmd=intf->cmdlist; cmd->func != NULL; cmd++) {
		if (strncmp(name, cmd->name, __maxlen(cmd->name, name)) == 0)
			break;
	}
	if (cmd->func == NULL) {
		cmd = intf->cmdlist;
		if (strncmp(cmd->name, "default", 7) == 0)
			return cmd->func(intf, argc+1, argv-1);

		lprintf(LOG_ERR, "Invalid command: %s", name);
		ipmi_cmd_print(intf->cmdlist);
		return -1;
	}
	return cmd->func(intf, argc, argv);
}

static void
ipmi_option_usage(const char * progname, struct ipmi_cmd * cmdlist, struct ipmi_intf_support * intflist)
{
	lprintf(LOG_NOTICE, "%s version %s\n", progname, VERSION);
	lprintf(LOG_NOTICE, "usage: %s [options...] <command>\n", progname);
	lprintf(LOG_NOTICE, "       -h             This help");
	lprintf(LOG_NOTICE, "       -V             Show version information");
	lprintf(LOG_NOTICE, "       -v             Verbose (can use multiple times)");
	lprintf(LOG_NOTICE, "       -c             Display output in comma separated format");
	lprintf(LOG_NOTICE, "       -d N           Specify a /dev/ipmiN device to use (default=0)");
	lprintf(LOG_NOTICE, "       -I intf        Interface to use");
	lprintf(LOG_NOTICE, "       -H hostname    Remote host name for LAN interface");
	lprintf(LOG_NOTICE, "       -p port        Remote RMCP port [default=623]");
	lprintf(LOG_NOTICE, "       -U username    Remote session username");
	lprintf(LOG_NOTICE, "       -f file        Read remote session password from file");
	lprintf(LOG_NOTICE, "       -z size        Change Size of Communication Channel (OEM)");
	lprintf(LOG_NOTICE, "       -S sdr         Use local file for remote SDR cache");
	lprintf(LOG_NOTICE, "       -D tty:b[:s]   Specify the serial device, baud rate to use");
	lprintf(LOG_NOTICE, "                      and, optionally, specify that interface is the system one");
#ifdef ENABLE_ALL_OPTIONS
	lprintf(LOG_NOTICE, "       -a             Prompt for remote password");
	lprintf(LOG_NOTICE, "       -Y             Prompt for the Kg key for IPMIv2 authentication");
	lprintf(LOG_NOTICE, "       -e char        Set SOL escape character");
	lprintf(LOG_NOTICE, "       -C ciphersuite Cipher suite to be used by lanplus interface");
	lprintf(LOG_NOTICE, "       -k key         Use Kg key for IPMIv2 authentication");
	lprintf(LOG_NOTICE, "       -y hex_key     Use hexadecimal-encoded Kg key for IPMIv2 authentication");
	lprintf(LOG_NOTICE, "       -L level       Remote session privilege level [default=ADMINISTRATOR]");
	lprintf(LOG_NOTICE, "                      Append a '+' to use name/privilege lookup in RAKP1");
	lprintf(LOG_NOTICE, "       -A authtype    Force use of auth type NONE, PASSWORD, MD2, MD5 or OEM");
	lprintf(LOG_NOTICE, "       -P password    Remote session password");
	lprintf(LOG_NOTICE, "       -E             Read password from IPMI_PASSWORD environment variable");
	lprintf(LOG_NOTICE, "       -K             Read kgkey from IPMI_KGKEY environment variable");
	lprintf(LOG_NOTICE, "       -m address     Set local IPMB address");
	lprintf(LOG_NOTICE, "       -b channel     Set destination channel for bridged request");
	lprintf(LOG_NOTICE, "       -t address     Bridge request to remote target address");
	lprintf(LOG_NOTICE, "       -B channel     Set transit channel for bridged request (dual bridge)");
	lprintf(LOG_NOTICE, "       -T address     Set transit address for bridge request (dual bridge)");
	lprintf(LOG_NOTICE, "       -l lun         Set destination lun for raw commands");
	lprintf(LOG_NOTICE, "       -o oemtype     Setup for OEM (use 'list' to see available OEM types)");
	lprintf(LOG_NOTICE, "       -O seloem      Use file for OEM SEL event descriptions");
	lprintf(LOG_NOTICE, "       -N seconds     Specify timeout for lan [default=2] / lanplus [default=1] interface");
	lprintf(LOG_NOTICE, "       -R retry       Set the number of retries for lan/lanplus interface [default=4]");
#endif
	lprintf(LOG_NOTICE, "");

	ipmi_intf_print(intflist);

	if (cmdlist != NULL)
		ipmi_cmd_print(cmdlist);
}
/* ipmi_catch_sigint  -  Handle the interrupt signal (Ctrl-C), close the
 *                       interface, and exit ipmitool with error (-1)
 *
 *                       This insures that the IOL session gets freed
 *                       for other callers.
 * 
 * returns -1
 */
void ipmi_catch_sigint()
{
	if (ipmi_main_intf != NULL) {
		printf("\nSIGN INT: Close Interface %s\n",ipmi_main_intf->desc);
		ipmi_main_intf->close(ipmi_main_intf);
	}
	exit(-1);
}

/* ipmi_parse_hex - convert hexadecimal numbers to ascii string
 *                  Input string must be composed of two-characer hexadecimal numbers.
 *                  There is no separator between the numbers. Each number results in one character
 *                  of the converted string.
 *
 *                  Example: ipmi_parse_hex("50415353574F5244") returns 'PASSWORD'
 *
 * @param str:  input string. It must contain only even number of '0'-'9','a'-'f' and 'A-F' characters.
 * @returns converted ascii string
 * @returns NULL on error
 */
static unsigned char *
ipmi_parse_hex(const char *str)
{
	const char * p;
	unsigned char * out, *q;
	unsigned char b = 0;
	int shift = 4;

	if (strlen(str) == 0)
		return NULL;

	if (strlen(str) % 2 != 0) {
		lprintf(LOG_ERR, "Number of hex_kg characters is not even");
		return NULL;
	}

	if (strlen(str) > (IPMI_KG_BUFFER_SIZE-1)*2) {
		lprintf(LOG_ERR, "Kg key is too long");
		return NULL;
	}

	out = calloc(IPMI_KG_BUFFER_SIZE, sizeof(unsigned char));
	if (out == NULL) {
		lprintf(LOG_ERR, "malloc failure");
		return NULL;
	}

	for (p = str, q = out; *p; p++) {
		if (!isxdigit(*p)) {
			lprintf(LOG_ERR, "Kg_hex is not hexadecimal number");
			free(out);
			out = NULL;
			return NULL;
		}

		if (*p < 'A') /* it must be 0-9 */
			b = *p - '0';
		else /* it's A-F or a-f */
			b = (*p | 0x20) - 'a' + 10; /* convert to lowercase and to 10-15 */

		*q = *q + b << shift;
		if (shift)
			shift = 0;
		else {
			shift = 4;
			q++;
		}
	}

	return out;
}


struct ipmi_intf *
ipmi_main_start(int argc, char ** argv,
		struct ipmi_cmd * cmdlist,
		struct ipmi_intf_support * intflist)
{
	struct ipmi_intf_support * sup;
	int privlvl = 0;
	uint8_t target_addr = 0;
	uint8_t target_channel = 0;

	uint8_t transit_addr = 0;
	uint8_t transit_channel = 0;
	uint8_t target_lun     = 0;
	uint8_t arg_addr = 0, addr;
	uint16_t my_long_packet_size=0;
	uint8_t my_long_packet_set=0;
	uint8_t lookupbit = 0x10;	/* use name-only lookup by default */
	int retry = 0;
	uint32_t timeout = 0;
	int authtype = -1;
	char * tmp_pass = NULL;
	char * tmp_env = NULL;

        // Bob: these pointers are kept in ipmi_intf
	char * hostname = NULL;
	char * username = NULL;
	char * password = NULL;
	char * intfname = NULL;
	char * oemtype  = NULL;
	char * seloem   = NULL;
	unsigned char * kgkey = NULL;
	char * sdrcache = NULL;
	char * devfile  = NULL; /* Bob: devfile name duplicated in ipmi_intf struct */
        // Bob: end of the list of pointers in ipmi_intf

	char * progname = NULL;
	int port = 0;
	int devnum = 0;
	int cipher_suite_id = 3; /* See table 22-19 of the IPMIv2 spec */
	int argflag, i, found;
	int rc = -1;
	char sol_escape_char = SOL_ESCAPE_CHARACTER_DEFAULT;
        struct ipmi_intf *intf = NULL;

	/* save program name */
	progname = strrchr(argv[0], '/');
	progname = ((progname == NULL) ? argv[0] : progname+1);
	signal(SIGINT, ipmi_catch_sigint);

	while ((argflag = getopt(argc, (char **)argv, OPTION_STRING)) != -1)
	{
		switch (argflag) {
		case 'I':
			if (intfname) {
				free(intfname);
				intfname = NULL;
			}
			intfname = strdup(optarg);
			if (intfname == NULL) {
				lprintf(LOG_ERR, "%s: malloc failure", progname);
				goto out_free;
			}
			if (intflist != NULL) {
				found = 0;
				for (sup=intflist; sup->name != NULL; sup++) {
					if (strncmp(sup->name, intfname, strlen(intfname)) == 0 &&
							strncmp(sup->name, intfname, strlen(sup->name)) == 0 &&
							sup->supported == 1)
						found = 1;
				}
				if (!found) {
					lprintf(LOG_ERR, "Interface %s not supported", intfname);
					goto out_free;
				}
			}
			break;
		case 'h':
			ipmi_option_usage(progname, cmdlist, intflist);
			rc = 0;
			goto out_free;
			break;
		case 'V':
			printf("%s version %s\n", progname, VERSION);
			rc = 0;
			goto out_free;
			break;
		case 'd':
			if (str2int(optarg, &devnum) != 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-d'.");
				rc = -1;
				goto out_free;
			}
			/* Check if device number is -gt 0; I couldn't find limit for
			 * kernels > 2.6, thus right side is unlimited.
			 */
			if (devnum < 0) {
				lprintf(LOG_ERR, "Device number %i is out of range.", devnum);
				rc = -1;
				goto out_free;
			}
			break;
		case 'p':
			if (str2int(optarg, &port) != 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-p'.");
				rc = -1;
				goto out_free;
			}
			/* Check if port is -gt 0 && port is -lt 65535 */
			if (port < 0 || port > 65535) {
				lprintf(LOG_ERR, "Port number %i is out of range.", port);
				rc = -1;
				goto out_free;
			}
			break;
		case 'C':
			if (str2int(optarg, &cipher_suite_id) != 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-C'.");
				rc = -1;
				goto out_free;
			}
			/* add check Cipher is -gt 0 */
			if (cipher_suite_id < 0) {
				lprintf(LOG_ERR, "Cipher suite ID %i is invalid.", cipher_suite_id);
				rc = -1;
				goto out_free;
			}
			break;
		case 'v':
			verbose++;
			break;
		case 'c':
			csv_output = 1;
			break;
		case 'H':
			if (hostname) {
				free(hostname);
				hostname = NULL;
			}
			hostname = strdup(optarg);
			if (hostname == NULL) {
				lprintf(LOG_ERR, "%s: malloc failure", progname);
				goto out_free;
			}
			break;
		case 'f':
			if (password) {
				free(password);
				password = NULL;
			}
			password = ipmi_password_file_read(optarg);
			if (password == NULL)
				lprintf(LOG_ERR, "Unable to read password "
						"from file %s", optarg);
			break;
		case 'a':
#ifdef HAVE_GETPASSPHRASE
			tmp_pass = getpassphrase("Password: ");
#else
			tmp_pass = getpass("Password: ");
#endif
			if (tmp_pass != NULL) {
				if (password) {
					free(password);
					password = NULL;
				}
				password = strdup(tmp_pass);
				tmp_pass = NULL;
				if (password == NULL) {
					lprintf(LOG_ERR, "%s: malloc failure", progname);
					goto out_free;
				}
			}
			break;
		case 'k':
			if (kgkey) {
				free(kgkey);
				kgkey = NULL;
			}
			kgkey = strdup(optarg);
			if (kgkey == NULL) {
				lprintf(LOG_ERR, "%s: malloc failure", progname);
				goto out_free;
			}
			break;
		case 'K':
			if ((tmp_env = getenv("IPMI_KGKEY"))) {
				if (kgkey) {
					free(kgkey);
					kgkey = NULL;
				}
				kgkey = strdup(tmp_env);
				if (kgkey == NULL) {
					lprintf(LOG_ERR, "%s: malloc failure", progname);
					goto out_free;
				}
			} else {
				lprintf(LOG_WARN, "Unable to read kgkey from environment");
			}
			break;
		case 'y':
			if (kgkey) {
				free(kgkey);
				kgkey = NULL;
			}
			kgkey = ipmi_parse_hex(optarg);
			if (kgkey == NULL) {
				goto out_free;
			}
			break;
		case 'Y':
#ifdef HAVE_GETPASSPHRASE
			tmp_pass = getpassphrase("Key: ");
#else
			tmp_pass = getpass("Key: ");
#endif
			if (tmp_pass != NULL) {
				if (kgkey) {
					free(kgkey);
					kgkey = NULL;
				}
				kgkey = strdup(tmp_pass);
				tmp_pass = NULL;
				if (kgkey == NULL) {
					lprintf(LOG_ERR, "%s: malloc failure", progname);
					goto out_free;
				}
			}
			break;
		case 'U':
			if (username) {
				free(username);
				username = NULL;
			}
			if (strlen(optarg) > 16) {
				lprintf(LOG_ERR, "Username is too long (> 16 bytes)");
				goto out_free;
			}
			username = strdup(optarg);
			if (username == NULL) {
				lprintf(LOG_ERR, "%s: malloc failure", progname);
				goto out_free;
			}
			break;
		case 'S':
			if (sdrcache) {
				free(sdrcache);
				sdrcache = NULL;
			}
			sdrcache = strdup(optarg);
			if (sdrcache == NULL) {
				lprintf(LOG_ERR, "%s: malloc failure", progname);
				goto out_free;
			}
			break;
		case 'D':
			/* check for subsequent instance of -D */
			if (devfile) {
				/* free memory for previous string */
				free(devfile);
			}
			devfile = strdup(optarg);
			if (devfile == NULL) {
				lprintf(LOG_ERR, "%s: malloc failure", progname);
				goto out_free;
			}
			break;
#ifdef ENABLE_ALL_OPTIONS
		case 'o':
			if (oemtype) {
				free(oemtype);
				oemtype = NULL;
			}
			oemtype = strdup(optarg);
			if (oemtype == NULL) {
				lprintf(LOG_ERR, "%s: malloc failure", progname);
				goto out_free;
			}
			if (strncmp(oemtype, "list", 4) == 0 ||
					strncmp(oemtype, "help", 4) == 0) {
				ipmi_oem_print();
				rc = 0;
				goto out_free;
			}
			break;
		case 'g':
			/* backwards compatible oem hack */
			if (oemtype) {
				free(oemtype);
				oemtype = NULL;
			}
			oemtype = strdup("intelwv2");
			break;
		case 's':
			/* backwards compatible oem hack */
			if (oemtype) {
				free(oemtype);
				oemtype = NULL;
			}
			oemtype = strdup("supermicro");
			break;
		case 'P':
			if (password) {
				free(password);
				password = NULL;
			}
			password = strdup(optarg);
			if (password == NULL) {
				lprintf(LOG_ERR, "%s: malloc failure", progname);
				goto out_free;
			}

			/* Prevent password snooping with ps */
			i = strlen(optarg);
			memset(optarg, 'X', i);
			break;
		case 'E':
			if ((tmp_env = getenv("IPMITOOL_PASSWORD"))) {
				if (password) {
					free(password);
					password = NULL;
				}
				password = strdup(tmp_env);
				if (password == NULL) {
					lprintf(LOG_ERR, "%s: malloc failure", progname);
					goto out_free;
				}
			}
			else if ((tmp_env = getenv("IPMI_PASSWORD"))) {
				if (password) {
					free(password);
					password = NULL;
				}
				password = strdup(tmp_env);
				if (password == NULL) {
					lprintf(LOG_ERR, "%s: malloc failure", progname);
					goto out_free;
				}
			}
			else {
				lprintf(LOG_WARN, "Unable to read password from environment");
			}
			break;
		case 'L':
			i = strlen(optarg);
			if ((i > 0) && (optarg[i-1] == '+')) {
				lookupbit = 0;
				optarg[i-1] = 0;
			}
			privlvl = str2val(optarg, ipmi_privlvl_vals);
			if (privlvl == 0xFF) {
				lprintf(LOG_WARN, "Invalid privilege level %s", optarg);
			}
			break;
		case 'A':
			authtype = str2val(optarg, ipmi_authtype_session_vals);
			break;
		case 't':
			if (str2uchar(optarg, &target_addr) != 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-t'.");
				rc = -1;
				goto out_free;
			}
			break;
		case 'b':
			if (str2uchar(optarg, &target_channel) != 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-b'.");
				rc = -1;
				goto out_free;
			}
			break;
		case 'T':
			if (str2uchar(optarg, &transit_addr) != 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-T'.");
				rc = -1;
				goto out_free;
			}
			break;
		case 'B':
			if (str2uchar(optarg, &transit_channel) != 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-B'.");
				rc = -1;
				goto out_free;
			}
			break;
		case 'l':
			if (str2uchar(optarg, &target_lun) != 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-l'.");
				rc = 1;
				goto out_free;
			}
			break;
		case 'm':
			if (str2uchar(optarg, &arg_addr) != 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-m'.");
				rc = -1;
				goto out_free;
			}
			break;
		case 'e':
			sol_escape_char = optarg[0];
			break;
		case 'O':
			if (seloem) {
				free(seloem);
				seloem = NULL;
			}
			seloem = strdup(optarg);
			if (seloem == NULL) {
				lprintf(LOG_ERR, "%s: malloc failure", progname);
				goto out_free;
			}
			break;
		case 'z':
			if (str2ushort(optarg, &my_long_packet_size) != 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-z'.");
				rc = -1;
				goto out_free;
			}
			break;
		/* Retry and Timeout */
		case 'R':
			if (str2int(optarg, &retry) != 0 || retry < 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-R'.");
				rc = -1;
				goto out_free;
			}
			break;
		case 'N':
			if (str2uint(optarg, &timeout) != 0) {
				lprintf(LOG_ERR, "Invalid parameter given or out of range for '-N'.");
				rc = -1;
				goto out_free;
			}
			break;
#endif
		default:
			ipmi_option_usage(progname, cmdlist, intflist);
			goto out_free;
		}
	}

	/* check for command before doing anything */
	if (argc-optind > 0 &&
			strncmp(argv[optind], "help", 4) == 0) {
		ipmi_cmd_print(cmdlist);
		rc = 0;
		goto out_free;
	}

	/*
	 * If the user has specified a hostname (-H option)
	 * then this is a remote access session.
	 *
	 * If no password was specified by any other method
	 * and the authtype was not explicitly set to NONE
	 * then prompt the user.
	 */
	if (hostname != NULL && password == NULL &&
			(authtype != IPMI_SESSION_AUTHTYPE_NONE || authtype < 0)) {
#ifdef HAVE_GETPASSPHRASE
		tmp_pass = getpassphrase("Password: ");
#else
		tmp_pass = getpass("Password: ");
#endif
		if (tmp_pass != NULL) {
			password = strdup(tmp_pass);
			tmp_pass = NULL;
			if (password == NULL) {
				lprintf(LOG_ERR, "%s: malloc failure", progname);
				goto out_free;
			}
		}
	}

	/* if no interface was specified but a
	 * hostname was then use LAN by default
	 * otherwise the default is hardcoded
	 * to use the first entry in the list
	 */
	if (intfname == NULL && hostname != NULL) {
		intfname = strdup("lan");
		if (intfname == NULL) {
			lprintf(LOG_ERR, "%s: malloc failure", progname);
			goto out_free;
		}
	}

	if (password != NULL && intfname != NULL) {
		if (strcmp(intfname, "lan") == 0 && strlen(password) > 16) {
			lprintf(LOG_ERR, "%s: password is longer than 16 bytes.", intfname);
			rc = -1;
			goto out_free;
		} else if (strcmp(intfname, "lanplus") == 0 && strlen(password) > 20) {
			lprintf(LOG_ERR, "%s: password is longer than 20 bytes.", intfname);
			rc = -1;
			goto out_free;
		}
	} /* if (password != NULL && intfname != NULL) */

	/* load interface */
        intf = ipmi_intf_load(intfname);

        // Bob: global intf instance, should be per session
	ipmi_main_intf = intf;

	if (intf == NULL) {
		lprintf(LOG_ERR, "Error loading interface %s", intfname);
		goto out_free;
	}

	/* setup log */
	log_init(progname, 0, verbose);

	/* run OEM setup if found */
	if (oemtype != NULL &&
	    ipmi_oem_setup(intf, oemtype) < 0) {
		lprintf(LOG_ERR, "OEM setup for \"%s\" failed", oemtype);
		goto out_free;
	}

	/* set session variables */
	if (hostname != NULL)
		ipmi_intf_session_set_hostname(intf, hostname);
	if (username != NULL)
		ipmi_intf_session_set_username(intf, username);
	if (password != NULL)
		ipmi_intf_session_set_password(intf, password);
	if (kgkey != NULL)
		ipmi_intf_session_set_kgkey(intf, kgkey);
	if (port > 0)
		ipmi_intf_session_set_port(intf, port);
	if (authtype >= 0)
		ipmi_intf_session_set_authtype(intf, (uint8_t)authtype);
	if (privlvl > 0)
		ipmi_intf_session_set_privlvl(intf, (uint8_t)privlvl);
	else
		ipmi_intf_session_set_privlvl(intf,
				IPMI_SESSION_PRIV_ADMIN);	/* default */
	/* Adding retry and timeout for interface that support it */
	if (retry > 0)
		ipmi_intf_session_set_retry(intf, retry);
	if (timeout > 0)
		ipmi_intf_session_set_timeout(intf, timeout);

	ipmi_intf_session_set_lookupbit(intf, lookupbit);
	ipmi_intf_session_set_sol_escape_char(intf, sol_escape_char);
	ipmi_intf_session_set_cipher_suite_id(intf, cipher_suite_id);

	intf->devnum = devnum;

	/* setup device file if given */
	intf->devfile = devfile;

	/* Open the interface with the specified or default IPMB address */
	intf->my_addr = arg_addr ? arg_addr : IPMI_BMC_SLAVE_ADDR;
	if (intf->open != NULL)
		intf->open(intf);

	/*
	 * Attempt picmg discovery of the actual interface address unless
	 * the users specified an address.
	 *	Address specification always overrides discovery
	 */
	if (picmg_discover(intf) && !arg_addr) {
		lprintf(LOG_DEBUG, "Running PICMG Get Address Info");
		addr = ipmi_picmg_ipmb_address(intf);
		lprintf(LOG_INFO,  "Discovered IPMB-0 address 0x%x", addr);
	}

	/*
	 * If we discovered the ipmb address and it is not the same as what we
	 * used for open, Set the discovered IPMB address as my address if the
	 * interface supports it.
	 */
	if (addr != 0 && addr != intf->my_addr &&
						intf->set_my_addr) {
		/*
		 * Only set the interface address on interfaces which support
		 * it
		 */
		(void) intf->set_my_addr(intf, addr);
	}

	/* If bridging addresses are specified, handle them */
	if (transit_addr > 0 || target_addr > 0) {
		/* sanity check, transit makes no sense without a target */
		if ((transit_addr != 0 || transit_channel != 0) &&
			target_addr == 0) {
			lprintf(LOG_ERR,
				"Transit address/channel %#x/%#x ignored. "
				"Target address must be specified!",
				transit_addr, transit_channel);
			goto out_free;
		}
		intf->target_addr = target_addr;
		intf->target_lun = target_lun ;
		intf->target_channel = target_channel ;

		intf->transit_addr    = transit_addr;
		intf->transit_channel = transit_channel;


		/* must be admin level to do this over lan */
		ipmi_intf_session_set_privlvl(intf, IPMI_SESSION_PRIV_ADMIN);
		/* Get the ipmb address of the targeted entity */
		intf->target_ipmb_addr =
					ipmi_picmg_ipmb_address(intf);
		lprintf(LOG_DEBUG, "Specified addressing     Target  %#x:%#x Transit %#x:%#x",
					   intf->target_addr,
					   intf->target_channel,
					   intf->transit_addr,
					   intf->transit_channel);
		if (intf->target_ipmb_addr) {
			lprintf(LOG_INFO, "Discovered Target IPMB-0 address %#x",
					   intf->target_ipmb_addr);
		}
	}

	lprintf(LOG_DEBUG, "Interface address: my_addr %#x "
			   "transit %#x:%#x target %#x:%#x "
			   "ipmb_target %#x\n",
			intf->my_addr,
			intf->transit_addr,
			intf->transit_channel,
			intf->target_addr,
			intf->target_channel,
			intf->target_ipmb_addr);

	/* parse local SDR cache if given */
	if (sdrcache != NULL) {
		ipmi_sdr_list_cache_fromfile(intf, sdrcache);
	}
	/* Parse SEL OEM file if given */
	if (seloem != NULL) {
		ipmi_sel_oem_init(seloem);
	}

	/* Enable Big Buffer when requested */
	intf->channel_buf_size = 0;
	if ( my_long_packet_size != 0 ) {
		printf("Setting large buffer to %i\n", my_long_packet_size);
		if (ipmi_kontronoem_set_large_buffer( intf, my_long_packet_size ) == 0)
		{
			my_long_packet_set = 1;
			intf->channel_buf_size = my_long_packet_size;
		}
	}

	intf->cmdlist = cmdlist;

#if 0
	/* now we finally run the command */
	if (argc-optind > 0)
		rc = ipmi_cmd_run(intf, argv[optind], argc-optind-1,
				&(argv[optind+1]));
	else
		rc = ipmi_cmd_run(intf, NULL, 0, NULL);
#endif
	if (my_long_packet_set == 1) {
		/* Restore defaults */
		ipmi_kontronoem_set_large_buffer( intf, 0 );
	}

	if (intfname != NULL) 
                intf->intfname = intfname;
        else
                intf->intfname = NULL;

	if (hostname != NULL) 
                intf->hostname = hostname;
        else
                intf->hostname = NULL;

	if (username != NULL) 
                intf->username = username;
        else
                intf->username = NULL;


	if (password != NULL) 
                intf->password = password;
        else
                intf->password = NULL;

	if (oemtype != NULL)
                intf->oemtype = oemtype;
        else
                intf->oemtype = NULL;

	if (seloem != NULL) 
                intf->seloem = seloem;
        else
                intf->seloem = NULL;

	if (kgkey != NULL) 
                intf->kgkey = kgkey;
        else
                intf->kgkey = NULL;

	if (sdrcache != NULL) 
                intf->sdrcache = sdrcache;
        else
                intf->sdrcache = NULL;

	if (devfile) 
                intf->devfile = devfile;
        else
                intf->devfile = NULL;

out_free:
        return intf;
}

int ipmi_main_finish(struct ipmi_intf *intf)
{
	/* clean repository caches */
	ipmi_cleanup(intf);

	/* call interface close function if available */
	if (intf->opened > 0 && intf->close != NULL)
		intf->close(intf);


	log_halt();

	if (intf->intfname != NULL) {
		free(intf->intfname);
		intf->intfname = NULL;
	}
	if (intf->hostname != NULL) {
		free(intf->hostname);
		intf->hostname = NULL;
	}
	if (intf->username != NULL) {
		free(intf->username);
		intf->username = NULL;
	}
	if (intf->password != NULL) {
		free(intf->password);
		intf->password = NULL;
	}
	if (intf->oemtype != NULL) {
		free(intf->oemtype);
		intf->oemtype = NULL;
	}
	if (intf->seloem != NULL) {
		free(intf->seloem);
		intf->seloem = NULL;
	}
	if (intf->kgkey != NULL) {
		free(intf->kgkey);
		intf->kgkey = NULL;
	}
	if (intf->sdrcache != NULL) {
		free(intf->sdrcache);
		intf->sdrcache = NULL;
	}
	if (intf->devfile) {
		free(intf->devfile);
		intf->devfile = NULL;
	}

	return 0;
}


struct ipmi_intf * ipmi_start_interface(char *intf_name, char *host, char *user, char *pass)
{
        int argc;
        char *argv[9];
        int rc;

        if (!intf_name) 
                intf_name  = "lan";
        argc = 9;
        argv[0] = "node-ffi-ipmi";
        argv[1] = "-I";
        argv[2] = intf_name;
        argv[3] = "-H";
        argv[4] = host;
        argv[5] = "-U";
        argv[6] = user;
        argv[7] = "-P";
        argv[8] = pass;

        return ipmi_main_start(argc, argv, ipmitool_cmd_list, NULL);
}

int ipmi_finish_interface(struct ipmi_intf *intf)
{
        return ipmi_main_finish(intf);
}


// Bob: had to split calls to ipmi_main_start() and ipmi_main_finish()
// so that multiple commands can be issued via API when this is used
// as a library, not just a command

// Note that this ipmi_main() is called in two places.
// in ipmievd.c and ipmitool.c 
// both are in ../src
// ipmishell.c does not seem to use it.
// ipmievd and impitool use different cmdlist which are
// passed to ipmi_main.

int
ipmi_main(int argc, char ** argv,
		struct ipmi_cmd * cmdlist,
		struct ipmi_intf_support * intflist)
{
        struct ipmi_intf *intf;

        if ((intf = ipmi_main_start(argc, argv, cmdlist, intflist)) == NULL) {
                lprintf(LOG_ERR, "cannot start ipmi");
                return -1;
        }

        return ipmi_main_finish(intf);
}


int
ipmi_run_command(struct ipmi_intf *intf, int argc, char *argv[])
{
        if (!intf)
                return -1;
        if (argc < 1)
                return -1;
        if (!argv || !argv[0])
                return -1;

        return ipmi_cmd_run(intf, argv[0], argc-1,&(argv[1]));
}
