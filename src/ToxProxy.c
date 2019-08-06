/*
 ============================================================================
 Name        : ToxProxy.c
 Authors     : Thomas Käfer, Zoff
 Version     : 0.1
 Copyright   : 2019

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

 ============================================================================
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>

#include <pthread.h>

#include <semaphore.h>
#include <signal.h>
#include <linux/sched.h>

// gives bin2hex & hex2bin functions for Tox-ID / public-key conversions
#include <sodium/utils.h>


// tox core
#include <tox/tox.h>

#undef TOX_HAVE_TOXUTIL
#define TOX_HAVE_TOXUTIL 1

#ifdef TOX_HAVE_TOXUTIL
    #include <tox/toxutil.h>
#endif

// timestamps for printf output
#include <time.h>
#include <sys/time.h>

// mkdir -> https://linux.die.net/man/2/mkdir
#include <sys/stat.h>
#include <sys/types.h>


typedef struct DHT_node {
    const char *ip;
    uint16_t port;
    const char key_hex[TOX_PUBLIC_KEY_SIZE*2 + 1];
    unsigned char key_bin[TOX_PUBLIC_KEY_SIZE];
} DHT_node;

#define CURRENT_LOG_LEVEL 9 // 0 -> error, 1 -> warn, 2 -> info, 9 -> debug
#define c_sleep(x) usleep_usec(1000*x)

typedef enum ControlProxyMessageType {
	ControlProxyMessageType_pubKey = 0,
	ControlProxyMessageType_killSwitch = 1,
	ControlProxyMessageType_allMessagesSent = 2
} ControlProxyMessageType;

FILE *logfile = NULL;
const char *log_filename = "ToxProxy.log";
const char *savedata_filename = "ToxProxy_SaveData.tox";
const char *savedata_tmp_filename = "ToxProxy_SaveData.tox.tmp";
const char *empty_log_message = "empty log message received!";
const char *msgsDir = "./messages";
const char *masterFile = "ToxProxyMasterPubKey.txt";

uint32_t tox_public_key_hex_size = 0; //initialized in main
uint32_t tox_address_hex_size = 0; //initialized in main
int tox_loop_running = 1;


void bin2upHex(const uint8_t *bin, uint32_t bin_size, char *hex, uint32_t hex_size)
{
	sodium_bin2hex(hex, hex_size, bin, bin_size);
	for (size_t i = 0; i < hex_size-1; i ++) {
		hex[i] = toupper(hex[i]);
	}
}

void toxProxyLog(int level, const char *msg, ...)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm tm = *localtime(&tv.tv_sec);

	if (msg == NULL || strlen(msg) < 1) // log message is NULL || length is 0 / negative
    {
    	msg = empty_log_message;
    }

	// 2019-08-03 17:01:04.440494 --> 4+1+2+1+2+1+2+1+2+1+2+1+6 = 26 ; [I] --> 5 ; + msg + \n
    char buffer[26+5+strlen(msg)+1]; // = "0000-00-00 00:00:00.000000 [_] msg\n" -- removed extra trailing \0\0.
    sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d.%06ld", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);
    strcat(buffer, " [_] ");

    switch (level)
    {
    	case 0:
    		buffer[28] = 'E';
    		break;
    	case 1:
    		buffer[28] = 'W';
    		break;
    	case 2:
    		buffer[28] = 'I';
    		break;
    	default:
    		if (level > 2)
        		buffer[28] = 'D';
    		else
        		buffer[28] = '?';
    		break;
    }
    strcat(buffer, msg);
    strcat(buffer, "\n");

    if (level <= CURRENT_LOG_LEVEL)
    {
        va_list ap;
        va_start(ap, msg);
        vprintf(buffer, ap);
        va_end(ap);

        if (logfile)
        {
            va_start(ap, msg);
        	vfprintf(logfile, buffer, ap);
            va_end(ap);
        }
    }
}

void killSwitch() {
	toxProxyLog(2, "got killSwitch command, deleting all data");
	unlink(savedata_filename);
	unlink(masterFile);
	toxProxyLog(1, "todo implement deleting messages");
	exit(0);
}

time_t get_unix_time(void) {
    return time(NULL);
}

void usleep_usec(uint64_t usec) {
    struct timespec ts;
    ts.tv_sec = usec / 1000000;
    ts.tv_nsec = (usec % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

void tox_log_cb__custom(Tox *tox, TOX_LOG_LEVEL level, const char *file, uint32_t line, const char *func,
                        const char *message, void *user_data)
{
    toxProxyLog(9, "%d:%s:%d:%s:%s", (int)level, file, (int)line, func, message);
}

Tox *create_tox()
{
    Tox *tox = NULL;

    struct Tox_Options options;

    tox_options_default(&options);

    // ----- set options ------
    options.ipv6_enabled = true;
    options.local_discovery_enabled = true;
    options.hole_punching_enabled = true;
    options.udp_enabled = true;
    options.tcp_port = 0; // disable tcp relay function!
    // ----- set options ------

    // set our own handler for c-toxcore logging messages!!
    options.log_callback = tox_log_cb__custom;


    FILE *f = fopen(savedata_filename, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);

        uint8_t *savedata = malloc(fsize);

        size_t ret = fread(savedata, fsize, 1, f);
        // TODO: handle ret return vlaue here!
        if (ret)
        {
            // ------
        }
        fclose(f);

        options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
        options.savedata_data = savedata;
        options.savedata_length = fsize;

#ifdef TOX_HAVE_TOXUTIL
        tox = tox_utils_new(&options, NULL);
#else
        tox = tox_new(&options, NULL);
#endif

        free(savedata);
    } else {
#ifdef TOX_HAVE_TOXUTIL
        tox = tox_utils_new(&options, NULL);
#else
        tox = tox_new(&options, NULL);
#endif
    }

    return tox;
}


void sigint_handler(int signo)
{
    if (signo == SIGINT)
    {
        printf("received SIGINT, pid=%d\n", getpid());
        tox_loop_running = 0;
    }
}


void update_savedata_file(const Tox *tox)
{
    size_t size = tox_get_savedata_size(tox);
    uint8_t *savedata = malloc(size);
    tox_get_savedata(tox, savedata);

    FILE *f = fopen(savedata_tmp_filename, "wb");
    fwrite(savedata, size, 1, f);
    fclose(f);

    rename(savedata_tmp_filename, savedata_filename);

    free(savedata);
}

void bootstrap(Tox *tox)
{
    DHT_node nodes[] =
    {
        {"178.62.250.138",             33445, "788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B", {0}},
        {"2a03:b0c0:2:d0::16:1",       33445, "788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B", {0}},
        {"tox.zodiaclabs.org",         33445, "A09162D68618E742FFBCA1C2C70385E6679604B2D80EA6E84AD0996A1AC8A074", {0}},
        {"163.172.136.118",            33445, "2C289F9F37C20D09DA83565588BF496FAB3764853FA38141817A72E3F18ACA0B", {0}},
        {"2001:bc8:4400:2100::1c:50f", 33445, "2C289F9F37C20D09DA83565588BF496FAB3764853FA38141817A72E3F18ACA0B", {0}},
        {"128.199.199.197",            33445, "B05C8869DBB4EDDD308F43C1A974A20A725A36EACCA123862FDE9945BF9D3E09", {0}},
        {"2400:6180:0:d0::17a:a001",   33445, "B05C8869DBB4EDDD308F43C1A974A20A725A36EACCA123862FDE9945BF9D3E09", {0}},
        {"node.tox.biribiri.org",      33445, "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67", {0}}
    };

    for (size_t i = 0; i < sizeof(nodes)/sizeof(DHT_node); i ++) {
        sodium_hex2bin(nodes[i].key_bin, sizeof(nodes[i].key_bin),
                       nodes[i].key_hex, sizeof(nodes[i].key_hex)-1, NULL, NULL, NULL);
        tox_bootstrap(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, NULL);
    }
}

void print_startup_message(Tox *tox)
{
    uint8_t tox_id_bin[tox_address_size()];
    tox_self_get_address(tox, tox_id_bin);
    char tox_id_hex[tox_address_hex_size];
    bin2upHex(tox_id_bin, tox_address_size(), tox_id_hex, tox_address_hex_size);

    size_t friends = tox_self_get_friend_list_size(tox);
    toxProxyLog(9, "ToxProxy startup completed");
    toxProxyLog(9, "My Tox ID = %s", tox_id_hex);
    toxProxyLog(9, "Number of friends = %ld", (long)friends);
}

void writeMessage(char *sender_key_hex, const uint8_t *message, size_t length)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm tm = *localtime(&tv.tv_sec);
    toxProxyLog(2,"New message from %s: %s", sender_key_hex, message);

    char userDir[tox_public_key_hex_size+strlen(msgsDir)+1];
    strcpy(userDir, msgsDir);
    strcat(userDir, "/");
    strcat(userDir, sender_key_hex);

    mkdir(msgsDir, 0700);
    mkdir(userDir, 0700);

    char timestamp[4+1+2+1+2+1+4+1+2+1+6] = "0000-00-00_0000-00,000000";
    snprintf(timestamp, sizeof(timestamp), "%d-%02d-%02d_%02d%02d-%02d,%ld", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);

    char msgPath[sizeof(userDir)+1+sizeof(timestamp)+4];
    strcpy(msgPath, userDir);
    strcat(msgPath, "/");
    strcat(msgPath, timestamp);
    strcat(msgPath, ".txt");

    FILE *f = fopen(msgPath, "wb");
    fwrite(message, length, 1, f);
    fclose(f);
}

void add_master(const char* public_key_hex)
{
	toxProxyLog(2, "added master");
    FILE *f = fopen(masterFile, "wb");
    fwrite(public_key_hex, tox_public_key_hex_size, 1, f);
    fclose(f);
}

bool is_master(const char* public_key_hex)
{
    FILE *f = fopen(masterFile, "rb");

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *masterPubKeyHexSaved = malloc(fsize);

	fread(masterPubKeyHexSaved, fsize, 1, f);
	fclose(f);

	if(strncmp(masterPubKeyHexSaved,public_key_hex, tox_public_key_hex_size) == 0) {
		return true;
	}
	else {
		return false;
	}
}

void getPubKeyHex_friendnumber(Tox *tox, uint32_t friend_number, char* pubKeyHex)
{
    uint8_t public_key_bin[tox_public_key_size()];
    tox_friend_get_public_key(tox, friend_number, public_key_bin, NULL);
    bin2upHex(public_key_bin, tox_public_key_size(), pubKeyHex, tox_public_key_hex_size);
}

bool is_master_friendnumber(Tox *tox, uint32_t friend_number)
{
	char pubKeyHex[tox_public_key_hex_size];
	getPubKeyHex_friendnumber(tox, friend_number, pubKeyHex);
	return is_master(pubKeyHex);
}

void friend_request_cb(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length,
                                   void *user_data)
{
    char public_key_hex[tox_public_key_hex_size];
	bin2upHex(public_key, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);

    size_t friends = tox_self_get_friend_list_size(tox);

    if(friends == 0) {
    	// add first friend as master for this proxy
    	add_master(public_key_hex);
    }

    toxProxyLog(2, "Got currently %zu friends. New friend request from %s with message: %s", friends, public_key_hex, message);

    writeMessage(public_key_hex, message, length);

    tox_friend_add_norequest(tox, public_key, NULL);
    update_savedata_file(tox);

    friends = tox_self_get_friend_list_size(tox);
    toxProxyLog(2, "Added friend: %s. Number of total friends: %zu", public_key_hex, friends);
}

void friend_message_cb(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                   size_t length, void *user_data)
{
    char *default_msg = "YOU are using the old Message format! this is not supported!";
    
    tox_friend_send_message(tox, friend_number, type,
                            (uint8_t *)default_msg,
                            strlen(default_msg), NULL);

    uint8_t public_key_bin[tox_public_key_size()];
    tox_friend_get_public_key(tox, friend_number, public_key_bin, NULL);
    char public_key_hex[tox_public_key_hex_size];
    bin2upHex(public_key_bin, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);
    writeMessage(public_key_hex, message, length);
}

void friendlist_onConnectionChange(Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status, void *user_data)
{
    toxProxyLog(2, "friendlist_onConnectionChange:*READY*:friendnum=%d %d", (int)friend_number, (int)connection_status);
    if(is_master_friendnumber(tox, friend_number)) {
    		if(connection_status != TOX_CONNECTION_NONE) {
    			toxProxyLog(2, "master is online, send him all cached unsent messages");
    		}
    		else {
    			toxProxyLog(2, "master went offline, don't send him any more messages.");
    		}
    }
}

void self_connection_status_cb(Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
    switch (connection_status) {
        case TOX_CONNECTION_NONE:
        	toxProxyLog(2, "Connection Status changed to: Offline");
            break;
        case TOX_CONNECTION_TCP:
        	toxProxyLog(2, "Connection Status changed to: Online via TCP");
            break;
        case TOX_CONNECTION_UDP:
        	toxProxyLog(2, "Connection Status changed to: Online via UDP");
            break;
    }
}

//
// cut message at 999 chars length !!
//
void send_text_message_to_friend(Tox *tox, uint32_t friend_number, const char *fmt, ...)
{
    toxProxyLog(9, "sending message to friend %d", friend_number);
    char msg2[1000];
    size_t length = 0;

    if (fmt == NULL)
    {
        toxProxyLog(9, "send_text_message_to_friend:no message to send");
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg2, 999, fmt, ap);
    va_end(ap);
    length = (size_t)strlen(msg2);
#ifdef TOX_HAVE_TOXUTIL
    uint32_t ts_sec = (uint32_t)get_unix_time();
    tox_util_friend_send_message_v2(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                    ts_sec, (const uint8_t *)msg2, length,
                                    NULL, NULL, NULL,
                                    NULL);
#else
    // old message format, not support by this proxy!
    tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *)msg2, length, NULL);
#endif
}

int hex_string_to_bin(const char *hex_string, size_t hex_len, char *output, size_t output_size)
{
    if (output_size == 0 || hex_len != output_size * 2) {
        return -1;
    }

    for (size_t i = 0; i < output_size; ++i) {
        sscanf(hex_string, "%2hhx", (unsigned char *)&output[i]);
        hex_string += 2;
    }

    return 0;
}

void friend_message_v2_cb(Tox *tox, uint32_t friend_number,
                       const uint8_t *raw_message, size_t raw_message_len)
{
    
    toxProxyLog(9, "enter friend_message_v2_cb");
    
#ifdef TOX_HAVE_TOXUTIL
    // now get the real data from msgV2 buffer
    uint8_t *message_text = calloc(1, raw_message_len);

    if (message_text)
    {
        // uint32_t ts_sec = tox_messagev2_get_ts_sec(raw_message);
        // uint16_t ts_ms = tox_messagev2_get_ts_ms(raw_message);
        uint32_t text_length = 0;
        bool res = tox_messagev2_get_message_text(raw_message,
                   (uint32_t)raw_message_len,
                   (bool)false, (uint32_t)0,
                   message_text, &text_length);
        toxProxyLog(9, "friend_message_v2_cb:fn=%d res=%d msg=%s", (int)friend_number, (int)res,
            (char *)message_text);

        if(is_master_friendnumber(tox, friend_number)) {
        		if(strlen(message_text) == strlen("fp:") + tox_public_key_size()*2)
        		{
        			if(strncmp(message_text, "fp:", strlen("fp:")))
				{
					char* pubKey = message_text+3;
					uint8_t public_key_bin[tox_public_key_size()];
					hex_string_to_bin(pubKey, tox_public_key_size()*2, public_key_bin, tox_public_key_size());
					tox_friend_add_norequest(tox, public_key_bin, NULL);
					update_savedata_file(tox);
				}
        		}
        		else if(strlen(message_text) == strlen("DELETE_EVERYTHING")) {
        			if(strncmp(message_text, "DELETE_EVERYTHING", strlen("DELETE_EVERYTHING")))
				{
        				killSwitch();
				}
        		}
        }
        else {
        		// nicht vom master, also wohl ein freund vom master.
        		uint8_t public_key_bin[tox_public_key_size()];
        	    tox_friend_get_public_key(tox, friend_number, public_key_bin, NULL);
        	    char public_key_hex[tox_public_key_hex_size];
        	    bin2upHex(public_key_bin, tox_public_key_size(), public_key_hex, tox_public_key_hex_size);
        	    writeMessage(public_key_hex, raw_message, raw_message_len);
        }

        // for now echo the message back to the friend
        send_text_message_to_friend(tox, friend_number, (char *)message_text);
        free(message_text);
    }

#endif
}

void friend_lossless_packet_cb(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
        void *user_data)
{
	toxProxyLog(0, "receiving custom message not yet implemented");

	if(length <= 0) {
		toxProxyLog(0, "received empty lossless package!");
		return;
	}

	if(!is_master_friendnumber(tox, friend_number)) {
		toxProxyLog(0, "received lossless package from somebody who's not master!");
		return;
	}

	if(data[0] == ControlProxyMessageType_killSwitch) {
		killSwitch();
	}
	else if (data[0] == ControlProxyMessageType_pubKey) {
		if(length != tox_public_key_size() + 1) {
			toxProxyLog(0, "received ControlProxyMessageType_pubKey message with wrong size");
			return;
		}
		const uint8_t* public_key = data+1;
	    tox_friend_add_norequest(tox, public_key, NULL);
	    update_savedata_file(tox);
	}
	else {
		toxProxyLog(0, "received unexpected ControlProxyMessageType");
	}
}

int main(int argc, char *argv[])
{
    logfile = fopen(log_filename, "wb");
    setvbuf(logfile, NULL, _IONBF, 0);

    toxProxyLog(2, NULL);

    Tox *tox = create_tox();

    tox_public_key_hex_size = tox_public_key_size()*2 + 1;
    tox_address_hex_size = tox_address_size()*2 + 1;

    const char *name = "ToxProxy";
    tox_self_set_name(tox, (uint8_t *)name, strlen(name), NULL);

    const char *status_message = "Proxy for your messages";
    tox_self_set_status_message(tox, (uint8_t *)status_message, strlen(status_message), NULL);

    bootstrap(tox);

    print_startup_message(tox);

    tox_callback_friend_request(tox, friend_request_cb);
    tox_callback_friend_message(tox, friend_message_cb);

#ifdef TOX_HAVE_TOXUTIL
    toxProxyLog(9, "using toxutil");
    tox_utils_callback_self_connection_status(tox, self_connection_status_cb);
    tox_callback_self_connection_status(tox, tox_utils_self_connection_status_cb);
    tox_utils_callback_friend_connection_status(tox, friendlist_onConnectionChange);
    tox_callback_friend_connection_status(tox, tox_utils_friend_connection_status_cb);
    tox_callback_friend_lossless_packet(tox, tox_utils_friend_lossless_packet_cb);
    // tox_utils_callback_file_recv_control(tox, on_file_control);
    tox_callback_file_recv_control(tox, tox_utils_file_recv_control_cb);
    // tox_utils_callback_file_chunk_request(tox, on_file_chunk_request);
    tox_callback_file_chunk_request(tox, tox_utils_file_chunk_request_cb);
    // tox_utils_callback_file_recv(tox, on_file_recv);
    tox_callback_file_recv(tox, tox_utils_file_recv_cb);
    // tox_utils_callback_file_recv_chunk(tox, on_file_recv_chunk);
    tox_callback_file_recv_chunk(tox, tox_utils_file_recv_chunk_cb);
    tox_utils_callback_friend_message_v2(tox, friend_message_v2_cb);
#else
    toxProxyLog(9, "NOT using toxutil");
    tox_callback_self_connection_status(tox, self_connection_status_cb);
    tox_callback_friend_connection_status(tox, friendlist_onConnectionChange);
#endif

    tox_callback_friend_lossless_packet(tox, friend_lossless_packet_cb);

    update_savedata_file(tox);


    long long unsigned int cur_time = time(NULL);
    long long loop_counter = 0;
    int max_tries = 2;
    int try = 0;
    uint8_t off = 1;

    while (1)
    {
        tox_iterate(tox, NULL);
        usleep_usec(tox_iteration_interval(tox) * 1000);

        if (tox_self_get_connection_status(tox) && off)
        {
            toxProxyLog(2, "Tox online, took %llu seconds", time(NULL) - cur_time);
            off = 0;
            break;
        }

        c_sleep(20);
        loop_counter++;

        if (loop_counter > (50 * 20))
        {
            try++;

            loop_counter = 0;
            // if not yet online, bootstrap every 20 seconds
            toxProxyLog(2, "Tox NOT online yet, bootstrapping again");
            bootstrap(tox);

            if (try >= max_tries)
            {
                // break the loop and start anyway
                // we will bootstrap again later if we are not online every few seconds
                break;
            }
        }
    }


    tox_loop_running = 1;
    signal(SIGINT, sigint_handler);
    pthread_setname_np(pthread_self(), "t_main");


    while (tox_loop_running) {
        tox_iterate(tox, NULL);
        usleep(tox_iteration_interval(tox) * 1000);
    }

#ifdef TOX_HAVE_TOXUTIL
    tox_utils_kill(tox);
#else
    tox_kill(tox);
#endif

    if (logfile)
    {
        fclose(logfile);
        logfile = NULL;
    }
    // HINT: for gprof you need an "exit()" call
    exit(0);
}
