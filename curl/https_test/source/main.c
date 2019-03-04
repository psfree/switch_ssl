#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <switch.h>
#include <curl/curl.h>
#include "mbedtls/debug.h"

#define SOCK_BUFFERSIZE 16384
#define _1MB 1048576


bool network_pre_init()
{
	static const SocketInitConfig socketInitConfig = {
		.bsdsockets_version = 1,

		.tcp_tx_buf_size = 1 * _1MB / 4,
		.tcp_rx_buf_size = 1 * _1MB / 4,
		.tcp_tx_buf_max_size = 2 * _1MB / 4,
		.tcp_rx_buf_max_size = 2 * _1MB / 4,

		.udp_tx_buf_size = 0x2400,
		.udp_rx_buf_size = 0xA500,

		.sb_efficiency = 8,

		.serialized_out_addrinfos_max_size = 0x1000,
		.serialized_out_hostent_max_size = 0x200,
		.bypass_nsd = false,
		.dns_timeout = 0,
	};

	Result ret = socketInitialize(&socketInitConfig);
	if (ret != 0)
	{
		return false;
	}

	return true;
}

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
	(void)data;
	randomGet(output, len);

	if (olen)
	{
		*olen = len;
	}
	return 0;
}

int debug_callback(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr)
{
	switch(type)
	{
		case CURLINFO_TEXT:
			printf("text: %s\n", data);
			break;
		default:
			printf("unknown data: %d, %d bytes\n", type, size);
	}
	return 0;
}

static size_t curlCallback(void *ptr, size_t size, size_t nmemb, void* f)
{
	size *= nmemb;
	
	printf("returned:\n%s\n", ptr);

	return size;
}


int main(int argc, char **argv)
{
    consoleInit(NULL);
	network_pre_init();
	
	curl_global_init(CURL_GLOBAL_ALL);

    CURL *curl = curl_easy_init();
	if (curl)
	{
		mbedtls_debug_set_threshold( 3 );
		curl_easy_setopt(curl, CURLOPT_SSLCERT, "sdmc:/client.pem");
		curl_easy_setopt(curl, CURLOPT_SSLKEY, "sdmc:/key.pem");
		curl_easy_setopt(curl, CURLOPT_CAINFO, NULL);
		curl_easy_setopt(curl, CURLOPT_CAPATH, NULL);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 0L);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, 0L);
		//curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, debug_callback);


		char sError[4096] = "";

		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, sError);
		curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, CURL_MAX_READ_SIZE);
		curl_easy_setopt(curl, CURLOPT_URL, "https://google.com/");
		//curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlImageCallback);
		//curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

		int r;
		if ((r = curl_easy_perform(curl)))
		{
			printf("network error code %d: %s\n", r, sError);
		}
		else
		{
			printf("success\n");
		}

		curl_easy_cleanup(curl);
	}
	
	while(appletMainLoop())
	{
		hidScanInput();

        //hidKeysDown returns information about which buttons have been just pressed (and they weren't in the previous frame)
        u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);

        if (kDown & KEY_PLUS) break; // break in order to return to hbmenu
	}

    socketExit();
    consoleExit(NULL);
    return 0;
}
