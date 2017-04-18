#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include "oscam-config-null.h"

/* maybe use it later
#if !defined(cs_conf)

    #define cs_conf "oscam.conf"
#endif
*/
#if !defined(cs_user)
    #define cs_user "oscam.user"
#endif
#if !defined(cs_server)
    #define cs_server "oscam.server"
#endif

FILE* conf_file(char fileName[]){

	FILE* file = fopen(fileName, "r");
	char *buffer;
	char *server_str;

	if(file == NULL) {
		int fd;
		if ( strncmp(fileName, cs_user, strlen(fileName)) == 0 ){
			char *user_str;
			char tempuser[] = "/tmp/oscam.user-XXXXXX"; fd=mkstemp(tempuser);
			strncpy(tmp_filename, tempuser, strlen(tempuser));
			user_str = (char *) malloc(48);
			snprintf(user_str, 48, "[account]\nuser = dvbapi_local\nau = 1\ngroup = 1\n\n");
			buffer = (char *) malloc(strlen(user_str));
			strncpy(buffer, user_str, 48);
			write(fd,buffer,strlen(buffer));
			file = fopen(tempuser, "r");
			tmp_conf = 1;
			free(user_str);
			free(buffer);
			unlink(tempuser);
		}

		else if ( strncmp(fileName, cs_server, strlen(fileName)) == 0 ){
			char tempserver[] = "/tmp/oscam.server-XXXXXX"; fd=mkstemp(tempserver);
			strncpy(tmp_filename, tempserver, strlen(tempserver));

			struct dirent **namelist;
			const char scandir1[] = "/dev";
			const char scandir2[] = "/dev/serial/by-id";
			int i=0, n=0, detect_index=0, ncount=0, cr=0;
			const char *devices[32];
			devices[0] = "sci0"; // intern 0
			devices[1] = "sci1"; // intern 1
			devices[2] = "usb-FTDI_FT232R_USB_UART_"; // Easy Mouse
			devices[3] = "usb-Argolis_Triple_Reader+_"; // Smargo Tripple+
			detect_index = 4; // 0 counts
			while (i < detect_index){

				//Internal
				if ( i < 2 ){
					ncount = 0;
					n = scandir(scandir1, &namelist, 0, alphasort);
					while (ncount < n){
						if(strstr(namelist[ncount++]->d_name, devices[i])){
							server_str = (char *) malloc(102);
							snprintf(server_str, 102, "[reader]\nlabel = %s\nprotocol = internal\ndetect = CD\ndevice = /dev/%s\ngroup = 1\nemmcache = 1,3,2\n\n", devices[i], devices[i]);
							buffer = (char *) malloc(strlen(server_str));
							strncpy(buffer, server_str, 102);
							write(fd,buffer,strlen(buffer));
							free(server_str);
							free(buffer);
							i++;
							tmp_conf = 1;
						}
					}
				}

				//Easymouse
				if ( i == 2 ){
				ncount = 0; cr=1;
				n = scandir(scandir2, &namelist, 0, alphasort);
					while (ncount < n){
						if(strstr(namelist[ncount++]->d_name, devices[i]))
						{
							server_str = (char *) malloc(256);
							snprintf(server_str, 256, "[reader]\nlabel = easymouse_%02d\nprotocol = mouse\ndetect = CD\ndevice = /dev/serial/by-id/%s\ngroup = 1\nemmcache = 1,3,2\n\n", cr, namelist[ncount-1]->d_name); cr++;
							buffer = (char *) malloc(strlen(server_str));
							strncpy(buffer, server_str, strlen(server_str));
							write(fd,buffer,strlen(buffer));
							free(server_str);
							free(buffer);
							tmp_conf = 1;
						}
					}
				}

				//Smargo Triple+
				if ( i == 3 ){
				char serial[9] = {0};
				ncount = 0; cr=1;
				n = scandir(scandir2, &namelist, 0, alphasort);
				while (ncount < n){
					if(strstr(namelist[ncount++]->d_name, devices[i]))
					{
						server_str = (char *) malloc(124);
						strncpy ( serial, namelist[ncount-1]->d_name+27, 8);
						snprintf(server_str, 124, "\n[reader]\nlabel = Smargo_TP%d\nprotocol = smartreader\ndevice = TripleP%i;Serial:%s\ndetect = CD\ngroup = 1\nemmcache = 1,3,2\n\n", cr, cr, serial); cr++;
						buffer = (char *) malloc(strlen(server_str));
						strncpy(buffer, server_str, strlen(server_str));
						write(fd,buffer,strlen(buffer));
						free(server_str);
						free(buffer);
						tmp_conf = 1;
					}}
				}

				i++;
			}
			if (tmp_conf == 1) {
				file = fopen(tempserver, "r");
			} else {
				file = NULL;
			}
		unlink(tempserver);
		}
	}
	return file;
}
